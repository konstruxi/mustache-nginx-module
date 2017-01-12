/**
 * @file   ngx_http_mustache_module.c
 * @author António P. P. Almeida <appa@perusio.net>
 * @date   Wed Aug 17 12:06:52 2011
 *
 * @brief  A hello world module for Nginx.
 *
 * @section LICENSE
 *
 * Copyright (C) 2011 by Dominic Fallows, António P. P. Almeida <appa@perusio.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#define HELPERS true
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdint.h>
#include <stdio.h>
#include "parser.lex.c"
#include "parser.tab.c"
#include "json.c"
#include "json.h"
#include "timestamp.c"

static ngx_int_t ngx_http_mustache_body_filter(ngx_http_request_t *r, ngx_chain_t *in);


//static ngx_int_t ngx_http_mustache_handler(ngx_http_request_t *r);

static ngx_http_request_body_filter_pt   ngx_http_next_request_body_filter;

static void *ngx_http_mustache_create_conf(ngx_conf_t *cf);
static char *ngx_http_mustache_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_mustache_init(ngx_conf_t *cf);

typedef struct {
    ngx_flag_t         enable;
    UJObject*        json;
    ngx_pool_t*        pool;
    char**             filenames;
    mustache_template_t**             results;
} ngx_http_mustache_conf_t;



/**
 * This module provided directive: mustache
 *
 */
static ngx_command_t ngx_http_mustache_commands[] = {

    { ngx_string("mustache"), /* directive */
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, /* location context and takes no arguments*/
      ngx_conf_set_flag_slot, /* configuration setup function */
      NGX_HTTP_LOC_CONF_OFFSET, /* No offset. Only one context is supported. */
      offsetof(ngx_http_mustache_conf_t, enable),
      NULL},

    ngx_null_command /* command termination */
};



/* The module context. */
static ngx_http_module_t ngx_http_mustache_module_ctx = {
    NULL, /* preconfiguration */
    ngx_http_mustache_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_mustache_create_conf, /* create location configuration */
    ngx_http_mustache_merge_conf /* merge location configuration */
};


/* Module definition. */
ngx_module_t ngx_http_mustache_module = {
    NGX_MODULE_V1,
    &ngx_http_mustache_module_ctx, /* module context */
    ngx_http_mustache_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

#include "value.c"
#include "render.c"
#include "template.c"




// merge parent-child configuration of mustache
static char *
ngx_http_mustache_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_mustache_conf_t *prev = parent;
    ngx_http_mustache_conf_t *conf = child;

    conf->pool = cf->pool;
    conf->filenames = prev->filenames;
    conf->results = prev->results;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}

// create mustache conf
static void *
ngx_http_mustache_create_conf(ngx_conf_t *cf)
{
    ngx_http_mustache_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mustache_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->filenames = ngx_pcalloc(cf->pool, sizeof(char *) * 100);
    ngx_memzero(conf->filenames, sizeof(char *) * 100);

    conf->results = ngx_pcalloc(cf->pool, sizeof(char *) * 100);
    ngx_memzero(conf->results, sizeof(char *) * 100);

    conf->pool = cf->pool;
    conf->enable = NGX_CONF_UNSET;

    return conf;
}






static ngx_int_t
ngx_http_mustache_init(ngx_conf_t *cf)
{ 
    ngx_http_next_request_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_mustache_body_filter;
    return NGX_OK;
}




static ngx_int_t
ngx_http_mustache_body_filter(ngx_http_request_t *r, ngx_chain_t *out)
{
  ngx_buf_t *b;

  ngx_http_mustache_conf_t    *conf;

  conf = ngx_http_get_module_loc_conf(r, ngx_http_mustache_module);

  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
             "catch request body filter");


  if (!conf->enable || out == NULL || r->header_only) {
      return ngx_http_next_request_body_filter(r, out);
  }

  char *json_source = (char *) out->buf->pos;
  // Bail out if not json
  if (out->buf->last == NULL || (out->buf->last - out->buf->pos) == 0 || 
         json_source == NULL || (json_source[0] != '[' && json_source[0] != '{')) {
    //fprintf(stdout, "not json\n");
    return ngx_http_next_request_body_filter(r, out);
  }

  //lame content-negotiation (without regard for qvalues)
  if(r->headers_in.accept) {
    u_char  *accept = r->headers_in.accept->value.data;
    u_char  *accept_html = ngx_strnstr(accept, "text/html", r->headers_in.accept->value.len);
    u_char  *accept_json = ngx_strnstr(accept, "application/json", r->headers_in.accept->value.len);
    if (accept_json != NULL && (accept_html == NULL || accept_html > accept_json)) {
      r->headers_out.content_type.data = (u_char *) "application/json";
      r->headers_out.content_type.len = sizeof("application/json") - 1;
      r->headers_out.content_type_lowcase = NULL;

      return ngx_http_next_request_body_filter(r, out);
    }
  }

  
  mustache_api_t api = {
      .read         = &ngx_mustache_read,
      .error        = &tests_error,
  };

  ngx_str_t template_name = ngx_string("html");
  mustache_template_t *template = ngx_get_mustache_template_by_variable_name(r, conf->pool, &template_name, &api);


  // Bail out if no template
  if (template == NULL) {
    //fprintf(stdout, "raw html is empty\n");
    return ngx_http_next_request_body_filter(r, out);
  }

  //fprintf(stdout, "par444sing json?, %p %p %d\n", out->buf->pos, r->main, out->buf->last - out->buf->last);
  //fprintf(stdout, "par444sing json?\n, %s", out->buf->pos);
  
  // Parse JSON
  void *state = NULL;
  UJObject json = UJDecode(json_source, ngx_buf_size(out->buf), NULL, &state, r);

  const char *error = UJGetError(state);
  if (error != NULL) {
    fprintf(stdout, "ERROR: %s\n", error);
    return ngx_http_next_request_body_filter(r, out);

  }

  //fprintf(stdout, "parsed json %p ~%.*s~ \n\n\n\n\n", json, (int) ngx_buf_size(out->buf), json_source);
  




  //fprintf(stdout, "raw html is not empty\n");

  b = ngx_create_temp_buf(r->pool, 4096 * 20);
  if (b == NULL) {
      return NGX_ERROR;
  }

  ngx_chain_t *cl  = NULL;
  cl = ngx_alloc_chain_link(r->pool);
  if (cl == NULL) {
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  cl->buf  = b;
  cl->next = NULL;


  out->next = cl;

  out->buf->last_buf = 0;
  b->last_buf = 1;
  
  // read out json in $meta variable to provide parent context value
  ngx_str_t meta_variable = ngx_string("meta");
  ngx_uint_t meta_variable_hash = ngx_hash_key(meta_variable.data, meta_variable.len);
  ngx_http_variable_value_t *meta_data = ngx_http_get_variable( r, &meta_variable, meta_variable_hash  );

  UJObject meta = NULL;
  void *metastate = NULL;
  //UJObject unwrapped;
  if (meta_data->len > 0 && (meta_data->data[0] == '[' || meta_data->data[0] == '{')) {
    //fprintf(stdout, "parsing meta  json %d\n", meta_data->len);
    meta = UJDecode((char *) meta_data->data, meta_data->len, NULL, &metastate, r);

    if (UJIsArray(meta))
      meta = (UJObject *) ((ArrayEntry *) ((ArrayItem *) meta)->head)->item;
       
       //fprintf(stdout, "parsed meta json %p \n", meta);
  }

  
  ngx_str_t before_template_name = ngx_string("before");
  mustache_template_t *before_template = ngx_get_mustache_template_by_variable_name(r, conf->pool, &before_template_name, &api);
  
  if (before_template != NULL) {
    //UJObject m = NULL;
    //void *iter = UJBeginArray(meta); 
    //UJIterArray(&iter, &m);
    

 
      //fprintf(stdout, "Rendering\n");
      ngx_mustache_render(r, b, before_template, meta, json, NULL, NULL);
      //fprintf(stdout, "Rendered\n");
    //}
  }
  // iterate main template if data is array
  if (UJIsArray(json)) {
    UJObject value;
    for (void *iter = UJBeginArray(json); UJIterArray(&iter, &value);)
      ngx_mustache_render(r, b, template, meta, value, NULL, NULL);
  } else if (UJIsObject(json)) {      
      ngx_mustache_render(r, b, template, meta, json, NULL, NULL);
  }


  // render after template
  ngx_str_t after_template_name = ngx_string("after");
  mustache_template_t *after_template = ngx_get_mustache_template_by_variable_name(r, r->pool, &after_template_name, &api);
  if (after_template != NULL) {
    ngx_mustache_render(r, b, after_template, meta, meta, NULL, NULL);
  }

  if (state)
  UJFree(state);
  if (metastate)
  UJFree(metastate);

  //b->start = b->pos;
  //b->end = b->last;
  b->memory = 1;
  *(b->last) = '\0';

  if (!r->header_sent) {
    r->headers_out.content_type.data = (u_char *) "text/html";
    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type_lowcase = NULL;
  }
    

  return ngx_http_next_request_body_filter(r, cl);
}


