
/**
 * Content handler.
 *
 * @param r
 *   Pointer to the request structure. See http_request.h.
 * @return
 *   The status of the response generation.
 */

typedef struct {
    UJObject              value;
    UJObject              parent;
    UJObject              grandparent;
    UJObject              meta;
    ngx_buf_t             *buffer;
    ngx_http_request_t    *r;
} render_context;

typedef struct {
    char                  *string;       ///< String to read or write
    ngx_int_t             len;           ///< String to read or write
    ngx_int_t              offset;       ///< Internal data. Current string offset.
} compile_context;


wchar_t *ctow(const char *buf, wchar_t *output) {
 wchar_t *cr = output;
    while (*buf) {
        *output++ = *buf++;
    }
    *output = 0;
    return cr;
}
uintmax_t ngx_mustache_render (ngx_http_request_t *r, ngx_buf_t *b, mustache_template_t *template, 
           UJObject *meta, UJObject *scope, UJObject *parent, UJObject *grandparent);

uintmax_t ngx_mustache_write(ngx_http_request_t *r, ngx_buf_t *b, char *buffer, ngx_int_t buffer_size){ // {{{
    //printf(buffer_size);
    
    for (ngx_int_t i = 0; i < buffer_size; i++) {
      if (buffer[i] == '\n' || buffer[i] == '\t' || buffer[i] == ' ') {
        if (*(b->last - 1) == '\n' || *(b->last - 1) == '\t' || *(b->last - 1) == ' ')
          continue;
      }
      *b->last++ = buffer[i];
    }

    return buffer_size || 1;
}


uintmax_t  ngx_mustache_variable(ngx_http_request_t *r, ngx_buf_t *b, mustache_token_variable_t *token, 
                                 UJObject *meta, UJObject *scope, UJObject *parent, UJObject *grandparent){
    
    int len = strlen(token->text);
    wchar_t token_text[len + 1];
    ctow(token->text, (wchar_t *) &token_text);
    
    // find key in context 

    UJObject* val = resolve_value(token_text, scope, parent, grandparent, meta, r, 1, b);

    if(val != NULL){
      if (UJIsInteger(val)) {
        char str[15];
        sprintf(str, "%d", UJNumericInt(val));
        return ngx_mustache_write(r, b, str, strlen(str));
      } else if (UJIsString(val)) {

        int len = ((StringItem *) val)->str.cchLen;
        char multibyte[len * 2];
        int multibytes = wcstombs(multibyte, ((StringItem *) val)->str.ptr, len * 2);

        return ngx_mustache_write(r, b, multibyte, multibytes);
      } else if (UJIsMBString(val)) {
        //fprintf(stdout, "got mbstr %s\n", token->text);
        return ngx_mustache_write(r, b, (char *) ((MBStringItem *) val)->str.ptr, ((MBStringItem *) val)->str.cchLen) || 1;
      }
    }
    return 1;
}
uintmax_t  ngx_mustache_section(ngx_http_request_t *r, ngx_buf_t *b, mustache_token_section_t *token, 
                                UJObject *meta, UJObject *scope, UJObject *parent, UJObject *grandparent){
       
    // find key in context 

    int len = strlen(token->name);
    wchar_t token_text[len + 1];
    ctow(token->name, (wchar_t *) &token_text);

    UJObject* val = resolve_value(token_text, scope, parent, grandparent, meta, r, 0, NULL);

    // negative condition
    if (token->inverted) {
      if (val == NULL || (UJIsInteger(val) && UJNumericInt(val) == 0))
        return ngx_mustache_render(r, b, token->section, meta, scope, parent, grandparent);
    } else if (val == NULL) {
    // render nested object (set subscope)
    } else if (UJIsObject(val)) {
      return ngx_mustache_render(r, b, token->section, meta, val, scope, parent);
    // iterate array (of arrays)
    } else if (UJIsArray(val)) {
      UJObject item;
      for (void *iter = UJBeginArray(val); UJIterArray(&iter, &item);) {
        if (UJIsArray(item)) {
          UJObject item2;
          for (void *iiter = UJBeginArray(item); UJIterArray(&iiter, &item2);) {
            ngx_mustache_render(r, b, token->section, meta, item2, scope, parent);
          }
        } else {
          ngx_mustache_render(r, b, token->section, meta, item, scope, parent);
        }
      }
    // positive condition
    } else if (token->section) {
      if (!UJIsInteger(val) || UJNumericInt(val) > 0)
        ngx_mustache_render(r, b, token->section, meta, scope, parent, grandparent);
    }
    return 1; 
}
void       tests_error(mustache_api_t *api, void *userdata, uintmax_t lineno, char *error){
    fprintf(stderr, "error: %d: %s\n", (int)lineno, error);
}


uintmax_t ngx_mustache_read(mustache_api_t *api, void *userdata, char *buffer, ngx_int_t buffer_size){ // {{{
    char                  *string;
    ngx_int_t              string_len;
    compile_context      *ctx               = (compile_context *)userdata; 
    
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



uintmax_t ngx_mustache_render (ngx_http_request_t *r, ngx_buf_t *b, mustache_template_t *template, 
           UJObject *meta, UJObject *scope, UJObject *parent, UJObject *grandparent){ // {{{
  mustache_template_t            *p;
  
  for(p = template; p; p = p->next){
    switch(p->type){
      case TOKEN_TEXT:
        ngx_mustache_write(r, b, p->token_simple.text, p->token_simple.text_length);
        break;
      case TOKEN_VARIABLE:
        ngx_mustache_variable(r, b, &p->token_simple, meta, scope, parent, grandparent);
        break;
      case TOKEN_SECTION:
        ngx_mustache_section(r, b, &p->token_section, meta, scope, parent, grandparent);
        break;
    };
  }
  return 1;
} // }}}
