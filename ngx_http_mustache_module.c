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

#define HELLO_WORLD ""

#define HELLO_WORLD2 "hello world"

static char *ngx_http_mustache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_mustache_body_filter(ngx_http_request_t *r, ngx_chain_t *in);


//static ngx_int_t ngx_http_mustache_handler(ngx_http_request_t *r);

static ngx_http_request_body_filter_pt   ngx_http_next_request_body_filter;

static void *ngx_http_mustache_create_conf(ngx_conf_t *cf);
static char *ngx_http_mustache_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_mustache_init(ngx_conf_t *cf);

typedef struct {
    ngx_flag_t         enable;
    json_value*        json;
    ngx_pool_t*        pool;
    char**             filenames;
    char**             results;
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

/* The hello world string. */
static u_char ngx_mustache[] = "";

/**
 * Content handler.
 *
 * @param r
 *   Pointer to the request structure. See http_request.h.
 * @return
 *   The status of the response generation.
 */

typedef struct {
    char                  *string;       ///< String to read or write
    ngx_int_t             len;           ///< String to read or write
    uintmax_t              offset;       ///< Internal data. Current string offset.
    json_value            *value;
    json_value            *parent;
    json_value            *grandparent;
    json_value            *meta;
    ngx_buf_t             *buffer;
    ngx_http_request_t    *r;
} render_context;






json_value* resolve_value(json_value *scope, char *string, json_value *parent, json_value *grandparent, json_value *meta, ngx_http_request_t *r, int fn) {
  int offset = 0;
  int size = strlen(string);
  json_value *current = scope;
  json_value *last = NULL;
  int op = 0;

  int i = offset;
  for (; i < size; i++) {

    // look ahead for special keywords
    if (string[i+0] == 'm' && string[i+1] == 'e' && string[i+2] == 't' && string[i+3] == 'a' && string[i+4] == ':') {
      current = meta;
      offset += 5;
      i += 5;
    }

    // look ahead for special keywords
    if (string[i+0] == 'p' && string[i+1] == 'a' && string[i+2] == 'r' 
     && string[i+3] == 'e' && string[i+4] == 'n' && string[i+5] == 't' && string[i+6] == ':') {
      // handle parent::
      if (grandparent != NULL && string[i+7] == ':') {
        //fprintf(stdout, "FOUND GRANDPARENT %d\n", i);
        offset += 8;
        i += 8;
        current = grandparent;
      // handle parent:
      } else if (parent != NULL) {
        if (string[i+7] == ':')
          return NULL;
        //fprintf(stdout, "FOUND PARENT %d\n", i);
        current = parent;
        i += 7;
        offset += 7;
      }
    }

    // {#parent:by:name}    aka   parent[this[name]] 
    // {#by:name}           aka   this[name]
    if (((string[i] == 'b' && string[i + 1] == 'y') 
      || (string[i] == 'i' && string[i + 1] == 's')) 
      &&  string[i + 2] == ':') {


      //fprintf(stdout, "FOUND op by %d \n", i);

      op = string[i] == 'b' ? 0 : 1;
      last = current;
      current = scope;


      i += 3;
      offset = i;
    }
    

    // scan string for property access
    if (i == size - 1 || string[i + 1] == ':' || string[i + 1] == '.') {

      //fprintf(stdout, "  REYOLVING %s %d\n", string + offset, i - offset);
      
      // step into first element of array
      if (current->type == json_array)
        current = current->u.array.values[0];

      if (current->type == json_object){
        json_int_t length = current->u.object.length;
        json_int_t x = 0;
        for (; x < length; x++) {
          if(strncmp(current->u.object.values[x].name, string + offset, i - offset + 1) == 0 &&
            strlen(current->u.object.values[x].name) == i - offset + 1){
            //fprintf(stdout, "  MATCHING\n");
            //fprintf(stdout, "  MATCHING %s  %d\n", string + offset, i);

            current = current->u.object.values[x].value;

            i += 1;
            offset = i + 1;
            break;
          }
        }
        if (x == length) {
          //if (last != NULL)
          //  break;
          return NULL;
        }
      } else if (current->type == json_integer) {
        int n = ngx_atoi(string + offset, i - offset);
        if(current->u.integer != n){
          return NULL;
        }
      // compare strings
      } else if (current->type == json_string) {
        if(strncmp(current->u.string.ptr, string + offset, i - offset) != 0){
          if (last != NULL) {
            // let it not escape 
            if (strncmp(string + offset, "HTML", 6) == 0) {
              fn = 0;
            } else if (strncmp(string + offset, "JSON", 4) == 0) {
              fn = 2;
            } else if (strncmp(string + offset, "DATETIME", 8) == 0) {
              fn = 3;
            } else if (strncmp(string + offset, "DATE", 4) == 0) {
              fn = 4;
            }
            fprintf(stdout, "BREAKING THIS TIME %s\n", string + offset);
            break;
          }
          return NULL;
        }
      // object key access
      }
    }
  }

  if (last != NULL) {
    if (op == 0) {
      if (last->type != json_object) {
        //fprintf(stdout, "Can only call :by on objects\n");
        return NULL;
      } else if (current == NULL || current->type != json_string) {
        //fprintf(stdout, ":by right side should be string\n");
        return NULL;
      } else {
        json_int_t length = last->u.object.length;
        json_int_t x = 0;
        for (; x < length; x++) {
          if(strncmp(last->u.object.values[x].name, current->u.string.ptr, current->u.string.length) == 0){
            current = last->u.object.values[x].value;
            break;
          }
        }
        if (x == length)
          return NULL;
      }
    // perform last == current
    } else if (op == 1) {
      if (last->type == json_string) {
        if (current->type != json_string 
        || strncmp(last->u.string.ptr, current->u.string.ptr, current->u.string.length) != 0)
          return NULL;
      } else if (last->type == json_integer) {
        if (current->type != json_integer || last->u.integer != current->u.integer)
          return NULL;
      }
    }
  }
  

  // strings can be transformed by fns
  if (current->type != json_string)  
    1;
  // escaped html
  else if (fn == 1) {

    int escape = ngx_escape_html(NULL, current->u.string.ptr, current->u.string.length);

    if (escape > 0) {
      //fprintf(stdout, "got to escape html len %d\n", escape);
      json_int_t len = current->u.string.length + escape;
      u_char *p = ngx_palloc(r->pool, len + 1);
      if (p == NULL) {
          return NGX_ERROR;
      }

      ngx_escape_html(p, current->u.string.ptr, current->u.string.length);
      p[len] = '\0';
      json_value  *ret = ngx_pcalloc(r->pool, sizeof(json_value));
      ret->type = json_string;
      ret->u.string.ptr = p;
      ret->u.string.length = len;
      current = ret;
      
      //fprintf(stdout, "got to escape html %s\n", p);

    }
    
  // escape json
  } else if (fn == 2) {

    //current = string_transforming_function(current, &ngx_escape_json);

    int escape = ngx_escape_json(NULL, current->u.string.ptr, current->u.string.length);
    
    // need to escape quotes?
    if (escape > 0) {
      // fprintf(stdout, "got to escape json %d\n", escape);
      int len = sizeof("''") - 1
          + current->u.string.length
          + escape + 1;
      
      u_char *p = ngx_palloc(r->pool, len + 1);
      if (p == NULL) {
          return NGX_ERROR;
      }

      ngx_escape_json(p, current->u.string.ptr, current->u.string.length);

      json_value  *ret = ngx_pcalloc(r->pool, sizeof(json_value));
      ret->type = json_string;
      ret->u.string.ptr = p;
      ret->u.string.length = len;
      current = ret;      
    }
  // format date & time
  } else if (fn == 3) {
    // parse time from iso8601
    timestamp_t ts;
    timestamp_parse(current->u.string.ptr, current->u.string.length, &ts);
    
    struct tm        tm;
    ngx_gmtime(ts.sec, &tm);

    
    char *p = ngx_palloc(r->pool, 256);
    if (p == NULL) {
        return NGX_ERROR;
    }
    
    json_value  *ret = ngx_pcalloc(r->pool, sizeof(json_value));
    ret->type = json_string;
    ret->u.string.ptr = p;
    fprintf(stdout, "num sec %d\n", ts.sec);
    
    ret->u.string.length = strftime((char *) p, 256,
                                    (char *) "%a %b %e %H:%M:%S %y %Y 444", &tm);

    ret->u.string.length = strftime((char *) p, 256,
                                    (char *) "%a %b %e %H:%M:%S %y %Y 444", &tm);
    if (ret->u.string.length != 0)
      current = ret;    
  // parse & format date
  } else if (fn == 4) {
    // parse time from iso8601
    timestamp_t ts;
    timestamp_parse(current->u.string.ptr, current->u.string.length, &ts);
    ngx_tm_t tm;
    ngx_gmtime(ts.sec, &tm);

    u_char *p = ngx_palloc(r->pool, sizeof("yyyy-mm-dd") - 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    fprintf(stdout, "date %d %d %d from %s\n", tm.ngx_tm_year, tm.ngx_tm_mon,
                tm.ngx_tm_mday, current->u.string.ptr);
    ngx_sprintf(p, "%04d-%02d-%02d", tm.ngx_tm_year, tm.ngx_tm_mon,
                tm.ngx_tm_mday);

    json_value  *ret = ngx_pcalloc(r->pool, sizeof(json_value));
    ret->type = json_string;
    ret->u.string.ptr = p;
    ret->u.string.length = sizeof("yyyy-mm-dd") - 1;;

    current = ret;   
  }
  switch (current->type) {
    case json_string:
      if (current->u.string.length == 0)
        return NULL;
      break;
    case json_array:
      if (current->u.array.length == 0)
        return NULL;
      break;
    case json_object:
      if (current->u.object.length == 0)
        return NULL;
      break;
    case json_null:
      return NULL;
  }
  return current;
}









uintmax_t  tests_varget(mustache_api_t *api, void *userdata, mustache_token_variable_t *token){
    render_context      *ctx               = (render_context *)userdata; 
    json_int_t length = ctx->value->u.object.length;
    
    // find key in context 

    json_value* val = resolve_value(ctx->value, token->text, ctx->parent, ctx->grandparent, ctx->meta, ctx->r, 1);
    if(val != NULL){
      if (val->type == json_integer) {
        char str[15];
        sprintf(str, "%d", val->u.integer);
        return api->write(api, userdata, str, strlen(str));
      }  else if (val->type == json_string) {
        return api->write(api, userdata, val->u.string.ptr, val->u.string.length) || 1;
      }
    }
    return 1;
}
uintmax_t  tests_sectget(mustache_api_t *api, void *userdata, mustache_token_section_t *token){
    render_context *ctx = (render_context *)userdata; 
    json_int_t length = ctx->value->u.object.length;
       
    // find key in context 
      //api->write(api, userdata, token->name, strlen(token->name));

    json_value* val = resolve_value(ctx->value, token->name, ctx->parent, ctx->grandparent, ctx->meta, ctx->r, 0);

    // render nested object
    if (token->inverted) {
      if (val == NULL || (val->type == json_integer && val->u.integer == 0))
        return mustache_render(api, userdata, token->section);
    } else if (val == NULL) {

    } else if (val->type == json_object) {
      json_value *old_grandparent = ctx->grandparent;
      ctx->grandparent = ctx->parent;

      json_value *old_parent = ctx->parent;
      ctx->parent = ctx->value;

      json_value *old = ctx->value;
      ctx->value = val;

      uintmax_t ret = mustache_render(api, userdata, token->section);
      ctx->value = old;
      ctx->parent = old_parent;
      ctx->grandparent = old_grandparent;
      return ret;
    // iterate array of objects
    } else if (val->type == json_array) {
      json_int_t len = val->u.array.length;
      uintmax_t ret = 1;


      for (json_int_t i = 0; i < len; i++) {
        json_value *item = val->u.array.values[i];

        if (item->type == json_array) {
          
          json_int_t len2 = item->u.array.length;
          for (json_int_t j = 0; j < len2; j++) {

            json_value *old_grandparent = ctx->grandparent;
            ctx->grandparent = ctx->value;

            json_value *old_parent = ctx->parent;
            ctx->parent = ctx->parent;

            json_value *old = ctx->value;
            ctx->value = item->u.array.values[j];

            ret = mustache_render(api, userdata, token->section);
            ctx->value = old;
            ctx->parent = old_parent;
            ctx->grandparent = old_grandparent;

          }
        } else {
          json_value *old_grandparent = ctx->grandparent;
          ctx->grandparent = ctx->parent;

          json_value *old_parent = ctx->parent;
          ctx->parent = ctx->value;

          json_value *old = ctx->value;
          ctx->value = val->u.array.values[i];

          ret = mustache_render(api, userdata, token->section);
          ctx->value = old;
          ctx->parent = old_parent;
          ctx->grandparent = old_grandparent;
        }
      }
      return ret;
    } else if (token->section) {
      if (val->type != json_integer || val->u.integer > 0)
        return mustache_render(api, userdata, token->section);
    }
    return 1; // error
}
void       tests_error(mustache_api_t *api, void *userdata, uintmax_t lineno, char *error){
    fprintf(stderr, "error: %d: %s\n", (int)lineno, error);
}


uintmax_t ngx_mustache_read(mustache_api_t *api, void *userdata, char *buffer, uintmax_t buffer_size){ // {{{
    char                  *string;
    uintmax_t              string_len;
    render_context      *ctx               = (render_context *)userdata; 
    
    if (ctx->offset == ctx->len)
      return 0;

    string     = ctx->string + ctx->offset;
    string_len = strlen(string);
    string_len = (string_len < buffer_size) ? string_len : buffer_size;
    if (string_len + ctx->offset >= ctx->len)
      string_len = ctx->len - ctx->offset;
    memcpy(buffer, string, string_len);

    //printf(string);
    //printf("\n");
    //printf("\n");
    //printf("%i-", string_len);
    //printf("%i\n", ctx->len);
    //printf("%i\n", ctx->offset);
    
    ctx->offset += string_len;

    return string_len;
}

uintmax_t ngx_mustache_write(mustache_api_t *api, void *userdata, char *buffer, uintmax_t buffer_size){ // {{{
    render_context      *ctx               = (render_context *)userdata; 
    ngx_buf_t           *b                 = (ngx_buf_t *) ctx->buffer;
    
    //printf(buffer_size);
    int i = 0;

    for (; i < buffer_size; i++) {
      if (buffer[i] == '\n' || buffer[i] == '\t' || buffer[i] == ' ') {
        if (*(b->last - 1) == '\n' || *(b->last - 1) == '\t' || *(b->last - 1) == ' ')
          continue;
      }
      *b->last++ = buffer[i];
    }

    return buffer_size || buffer_size;
}







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


/**
 * Configuration setup function that installs the content handler.
 *
 * @param cf
 *   Module configuration structure pointer.
 * @param cmd
 *   Module directives structure pointer.
 * @param conf
 *   Module configuration structure pointer.
 * @return string
 *   Status of the configuration setup.
 */
//static char *ngx_http_mustache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
//{
//    ngx_http_core_loc_conf_t *clcf; /* pointer to core location configuration */
//
//    /* Install the hello world handler. */
//    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
//    clcf->handler = ngx_http_mustache_handler;
//
//    return NGX_CONF_OK;
//} /* ngx_http_mustache */

ngx_buf_t* find_request_body_buffer(ngx_http_request_t *r) {
  ngx_chain_t                 *cl,*nl;
  ngx_buf_t  *b;

  if (!r->request_body || !r->request_body->bufs)
      return NULL;
  if (r->request_body->buf && r->request_body->buf->last - r->request_body->buf->pos > 0)
    return r->request_body->buf;
//  fprintf(stdout, "r->request_body%p\n", r->request_body);
//  fprintf(stdout, "r->parent->request_body%p\n", r->parent->request_body);
//  fprintf(stdout, "r->parent%p\n", r->parent);
//  fprintf(stdout, "r%p\n", r);
  for (cl = r->parent->request_body->bufs; cl; cl = cl->next) {
    //if (ngx_buf_special(cl->buf)) {
    //    /* we do not want to create zero-size bufs */
    //    continue;
    //}

    b = ngx_alloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(b, cl->buf, sizeof(ngx_buf_t));
    b->tag = (ngx_buf_tag_t) &find_request_body_buffer;
    b->last_buf = 0;
    b->last_in_chain = 0;


//    fprintf(stdout, "found buffer, %s %p\n", b->pos, r);
//    fprintf(stdout, "found buffer, %s %p\n", b->pos, r->parent);
    if (b->pos != NULL && b->last != NULL)
//    fprintf(stdout, "length buffer, %d\n", (b->last - b->pos));

    if (b->last - b->pos > 0 || !cl->next)
      return b;
  }
  return NULL;
}


mustache_template_t   *
ngx_get_mustache_template(ngx_http_request_t *r, ngx_pool_t* pool, char *path, size_t size, mustache_api_t *api) {
  ngx_str_t                   name;
  ngx_file_t                  file;
  ngx_file_info_t             fi;
  ngx_err_t                   err;
  ngx_memzero(&file, sizeof(ngx_file_t));

  ngx_http_mustache_conf_t    *conf;
  conf = ngx_http_get_module_loc_conf(r, ngx_http_mustache_module);

  ngx_str_t views_variable = ngx_string("views");
  ngx_uint_t views_variable_hash = ngx_hash_key(views_variable.data, views_variable.len);
  ngx_http_variable_value_t *prefix = ngx_http_get_variable( r, &views_variable, views_variable_hash  );

  char* data = ngx_pnalloc(conf->pool, size + prefix->len + 6);
  memcpy(data, prefix->data, prefix->len);
  memcpy(data + prefix->len, path, size);
  data[prefix->len + size] = '\0';


  render_context srcstr = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};


  int cached_i = 0;
  for (; cached_i < 100 && conf->filenames[cached_i] != NULL; cached_i++) {
    if (strncmp(conf->filenames[cached_i], data, prefix->len + size + 1 ) == 0) {
      return conf->results[cached_i];
    }
  }

  file.name = name;
  file.log = ngx_cycle->log;
  name.data = data;
  name.len = size + prefix->len + 5;


  file.fd = ngx_open_file(name.data, NGX_FILE_RDONLY, 0, 0);
  if (file.fd == NGX_INVALID_FILE) {
      err = ngx_errno;
      if (err != NGX_ENOENT) {
          fprintf(stdout, " \"%s\" failed\n", name.data);
      }
      return NGX_DECLINED;
  }

  if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
      goto failed;
  }

  if (ngx_file_info(name.data, &fi) == NGX_FILE_ERROR) {
      goto failed;
  }

  size_t fsize = ngx_file_size(&fi);
  time_t mtime = ngx_file_mtime(&fi);

  char *base = ngx_palloc(conf->pool, fsize + 1);
  if (base == NULL) {
      goto failed;
  }

  size_t n = ngx_read_file(&file, base, fsize, 0);
  base[fsize] = '\0';

  goto done;
failed:
  //fprintf(stdout, "Failed\n");
  return NULL;
done:

  //fprintf(stdout, "Writing cache at %d\n", cached_i);



  srcstr.string = base;
  srcstr.len = strlen(base);
  srcstr.offset = 0;


  mustache_template_t   *template = mustache_compile(api, &srcstr);


  conf->filenames[cached_i] = data;
  conf->results[cached_i] = template;

  //fprintf(stdout, "Success %d\n", strlen(base));
  return template;
}

mustache_template_t   *ngx_get_mustache_template_by_variable_name(ngx_http_request_t *r, ngx_pool_t* pool, ngx_str_t *html_variable, mustache_api_t *api) {
  
  // get parsed mustache template by variable name


  ngx_uint_t html_variable_hash = ngx_hash_key(html_variable->data, html_variable->len);
  ngx_http_variable_value_t *raw_html = ngx_http_get_variable( r, html_variable, html_variable_hash  );

//    fprintf(stdout, "raw_html %s\n", raw_html->data);
//    fprintf(stdout, "raw_html %s\n", html_variable->data);
  if (raw_html->len < 256 && raw_html->len > 0) {
//    fprintf(stdout, "raw_html %s\n", raw_html->data);
    int i = 0;
    for (; i < raw_html->len; i++)
      if (raw_html->data[i] == '\n')
        break;
    if (i == raw_html->len) {
      return ngx_get_mustache_template(r, pool, raw_html->data, raw_html->len, api);
    }
  }
  return NULL;
}


static ngx_int_t
ngx_http_mustache_body_filter(ngx_http_request_t *r, ngx_chain_t *out)
{
  ngx_buf_t *b;

  u_char                      *p;
  ngx_http_mustache_conf_t    *conf;

  conf = ngx_http_get_module_loc_conf(r, ngx_http_mustache_module);

  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
             "catch request body filter");


  if (out == NULL || r->header_only) {
      return ngx_http_echo_next_body_filter(r, out);
  }
  if (!conf->enable) {
      return ngx_http_next_request_body_filter(r, out);
  }


  char *json_source = out->buf->pos;
  // Bail out if not json
  if (json_source == NULL || (json_source[0] != '[' && json_source[0] != '{')) {
    //fprintf(stdout, "not json\n");
    return ngx_http_next_request_body_filter(r, out);
  }

  mustache_api_t api = {
      .read         = &ngx_mustache_read,
      .write        = &ngx_mustache_write,
      .varget       = &tests_varget,
      .sectget      = &tests_sectget,
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
  json_value *json = json_parse(json_source, ngx_buf_size(out->buf));
  //fprintf(stdout, "parsed json\n");


  
  //fprintf(stdout, "raw html is not empty\n");

  b = ngx_create_temp_buf(r->pool, 4096 * 10);
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

  json_value *meta = NULL;
  if (meta_data->len > 0 && (meta_data->data[0] == '[' || meta_data->data[0] == '{')) {
    //fprintf(stdout, "parsing meta  json %d\n", meta_data->len);
    meta = json_parse(meta_data->data, meta_data->len);
    
    // pick first item in array
    if (meta->type == json_array)
      meta = meta->u.array.values[0];
    //fprintf(stdout, "parsed meta json\n");
  }


  render_context srcstr = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
  render_context mustache_render_context = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, b};


  ngx_str_t before_template_name = ngx_string("before");
  mustache_template_t *before_template = ngx_get_mustache_template_by_variable_name(r, conf->pool, &before_template_name, &api);
  if (before_template != NULL) {
    if (json && json->type == json_array)
      mustache_render_context.parent = json->u.array.values[0];
    else
      mustache_render_context.parent = json;

    mustache_render_context.parent = json;
    mustache_render_context.meta   = meta;
    mustache_render_context.value  = meta;
    mustache_render(&api, &mustache_render_context, before_template);
  }
  
  mustache_render_context.parent = meta;
  mustache_render_context.meta   = meta;
  mustache_render_context.r = r;
  // iterate main template if data is array
  if (json->type == json_array) {
    int length = json->u.array.length;
    for (int x = 0; x < length; x++) {
        mustache_render_context.value = json->u.array.values[x];
        mustache_render(&api, &mustache_render_context, template);
    }
  } else if (json->type == json_object) {      
    mustache_render_context.value = json;
    mustache_render(&api, &mustache_render_context, template);
  }


  // render after template
  ngx_str_t after_template_name = ngx_string("after");
  mustache_template_t *after_template = ngx_get_mustache_template_by_variable_name(r, conf->pool, &after_template_name, &api);
  if (after_template != NULL) {
    mustache_render_context.value = meta;
    if (json && json->type == json_array)
      mustache_render_context.parent = json->u.array.values[0];
    else
      mustache_render_context.parent = json;
    mustache_render(&api, &mustache_render_context, after_template);
  }

  mustache_render_context.r = NULL;

  json_value_free(json);
  if (meta != NULL)
    json_value_free(meta);

  //b->start = b->pos;
  //b->end = b->last;
  b->memory = 1;

  if (!r->header_sent) {
    r->headers_out.content_type.data = (u_char *) "text/html";
    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type_len = sizeof("text/html") - 1;

    r->headers_out.content_type_lowcase = NULL;
  }
    

  return ngx_http_next_request_body_filter(r, cl);
}


