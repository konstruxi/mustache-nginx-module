
UJObject* resolve_value(wchar_t *string, UJObject *scope, UJObject *parent, UJObject *grandparent, UJObject *meta, ngx_http_request_t *r, int fn, ngx_buf_t* b) {
  size_t offset = 0;
  size_t size = wcslen(string);
  UJObject *current = scope;
  UJObject *last = NULL;
  int op = 0;

  //fprintf(stdout, "Resolving value: %ls %p\n", string, current);

  size_t i = offset;
  for (; i < size; i++) {

    // resolve nginx variable
    if (string[i+0] == 'v' && string[i+1] == 'a' && string[i+2] == 'r' && string[i+3] == 's' && string[i+4] == ':') {
      ngx_str_t request_variable;

      char multibyte[32];
      request_variable.data = (u_char *) &multibyte;
      request_variable.len = 0;

      while (i + 5 + request_variable.len < size && string[i + 5 + request_variable.len] != ':') {
        multibyte[request_variable.len] = string[i + 5 + request_variable.len];
        request_variable.len++;
      }

      multibyte[request_variable.len] = '\0';

      ngx_uint_t request_variable_hash = ngx_hash_key(request_variable.data, request_variable.len);
      ngx_http_variable_value_t *request_value = ngx_http_get_variable( r, &request_variable, request_variable_hash  );

      if (request_value->len == 0 || request_value->not_found) {
        return NULL;
      } else {
        MBStringItem  *ret = ngx_pcalloc(r->pool, sizeof(MBStringItem));
        ret->item.type = UJT_MBString;
        ret->str.ptr = request_value->data;
        ret->str.cchLen = request_value->len;
        current = (UJObject *) ret; 
      }

      i += 5 + request_variable.len + 1;
      offset += 5 + request_variable.len + 1;
    }

    // look ahead for special keywords
    if (string[i+0] == 'm' && string[i+1] == 'e' && string[i+2] == 't' && string[i+3] == 'a' && string[i+4] == ':') {
      current = meta;
      offset += 5;
      i += 5;
    }
    if (string[i+0] == 't' && string[i+1] == 'h' && string[i+2] == 'i' && string[i+3] == 's') {
      if (i == size - 4) {
        current = scope;
        offset += 4;
        i += 4;
      } else if (string[i + 4] == ':') {
        current = scope;
        offset += 5;
        i += 5;
      }
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
      || (string[i] == 'i' && string[i + 1] == 's') 
      || (string[i] == 'i' && string[i + 1] == 'n') 
      || (string[i] == 'e' && string[i + 1] == 'q')) 
      &&  string[i + 2] == ':') {


      //fprintf(stdout, "FOUND op by %d \n", i);

      op = string[i] == 'b' ? 0 : string[i] == 'e' ? 3 : string[i + 1] == 's' ? 1 : 2;
      last = current;
      current = scope;


      i += 2;
      offset += 3;
      continue;
    }
    
    //UJObject unwrapped;

    // scan string for property access
    if (i == size - 1 || string[i + 1] == ':' || string[i + 1] == '.') {

      // step into first element of array
      if (UJIsArray(current)) {
        current = (UJObject *) ((ArrayEntry *) ((ArrayItem *) current)->head)->item;
        return NULL;
      }

      if (UJIsObject(current)){
        UJObject value;
        UJString key;
        //fprintf(stdout, "Finding in object %ls\n", string);
        int iterating = 1;
        for (void *iter = UJBeginObject(current); (iterating = UJIterObject(&iter, &key, &value));) {

          if(wcsncmp(key.ptr, string + offset, i - offset + 1) == 0 &&
            key.cchLen == i - offset + 1){
            //fprintf(stdout, "  MATCHING\n");
            //fprintf(stdout, "  MATCHING %s  %d\n", string + offset, i);

            current = value;

            i += 1;
            offset = i + 1;

            break;
          }
        }
        if (iterating == 0) {
          //if (last != NULL)
          //  break;
          return NULL;
        }
      } else if (UJIsInteger(current)) {
        int n = ngx_atoi((u_char *) string + offset, i - offset);
        if(UJNumericInt(current) != n){
          return NULL;
        }
      // compare strings
      } else if (UJIsString(current)) {
        if(wcsncmp(((StringItem *) current)->str.ptr, string + offset, i - offset) != 0
                || ((StringItem *) current)->str.cchLen != i - offset + 1){
          if (last != NULL) {
            // let it not escape 
            if (wcsncmp(string + offset, L"HTML", 4) == 0) {
              fn = 0;
            } else if (wcsncmp(string + offset, L"JSON", 4) == 0) {
              fn = 2;
            } else if (wcsncmp(string + offset, L"DATETIME", 8) == 0) {
              fn = 3;
            } else if (wcsncmp(string + offset, L"DATE", 4) == 0) {
              fn = 4;
            }
            //fprintf(stdout, "BREAKING THIS TIME %ls\n", string + offset);
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
      if (!UJIsObject(last)) {
        //fprintf(stdout, "Can only call :by on objects\n");
        return NULL;
      } else if (current == NULL || !UJIsString(current)) {
        //fprintf(stdout, ":by right side should be string\n");
        return NULL;
      } else {
        UJObject value;
        UJString key;
        UJString str = ((StringItem *) current)->str;
        
        int iterating = 1;
        for (void *iter = UJBeginObject(last); (iterating = UJIterObject(&iter, &key, &value));) {
          if(str.cchLen == key.cchLen && wcsncmp(key.ptr, str.ptr, str.cchLen) == 0){
            current = value;
            break;
          }
        }
        if (iterating == 0)
          return NULL;
      }
    // perform last == current
    } else if (op == 1) {
      if (UJIsString(last)) {
        if (!UJIsString(current) 
        || wcsncmp(((StringItem *) last)->str.ptr, 
                   ((StringItem *) current)->str.ptr, 
                   ((StringItem *) current)->str.cchLen) != 0)
          return NULL;
      } else if (UJIsInteger(last)) {
        if (!UJIsInteger(current) || UJNumericInt(last) != UJNumericInt(current))
          return NULL;
      }
    // perform in
    } else if (op == 2) {
      //...
    }
  }
  // strings can be transformed by fns
  if (!UJIsString(current)) {

  }
  // escaped html
  else if (fn == 1) {
    int len = ((StringItem *) current)->str.cchLen;
    char multibyte[len * 2];
    int multibytes = wcstombs(multibyte, ((StringItem *) current)->str.ptr, len * 2);

    //fprintf(stdout, "escaping [%d / %d] [%.*S]\n", multibytes, len,  len * 2, ((StringItem *) current)->str.ptr);

    int escape = ngx_escape_html(NULL, (u_char *) multibyte, multibytes);

    if (escape > 0) {
      //fprintf(stdout, "got to escape html len %d\n", escape);
      int len = multibytes + escape;
      u_char *p = ngx_palloc(r->pool, len + 1);
      if (p == NULL) {
          return NULL;
      }
      
      ngx_escape_html((u_char *) p, (u_char *) multibyte, multibytes);
      p[len] = '\0';
      MBStringItem  *ret = ngx_pcalloc(r->pool, sizeof(MBStringItem));
      ret->item.type = UJT_MBString;
      ret->str.ptr = p;
      ret->str.cchLen = len;
      current = (UJObject *) ret;
      
      //fprintf(stdout, "got to escape html %s\n", p);

    }
    
  // escape json
  } else if (fn == 2) {

    //current = string_transforming_function(current, &ngx_escape_json);

    int len = ((StringItem *) current)->str.cchLen;
    char multibyte[len * 2];
    int multibytes = wcstombs(multibyte, ((StringItem *) current)->str.ptr, len * 2);

    int escape = ngx_escape_json(NULL, (u_char *) multibyte, multibytes);
    
    // need to escape quotes?
    if (escape > 0) {
      // fprintf(stdout, "got to escape json %d\n", escape);
      int len = sizeof("''") - 1
          + multibytes
          + escape + 1;
      
      u_char *p = ngx_palloc(r->pool, len + 1);
      if (p == NULL) {
          return NULL;
      }

      ngx_escape_json((u_char *) p, (u_char *) multibyte, multibytes);

      MBStringItem  *ret = ngx_pcalloc(r->pool, sizeof(MBStringItem));
      ret->item.type = UJT_MBString;
      ret->str.ptr = p;
      ret->str.cchLen = len;
      current = (UJObject *) ret;  
    }
  // format date & time
  } else if (fn == 3) {
    int len = ((StringItem *) current)->str.cchLen;
    char multibyte[len * 2];
    int multibytes = wcstombs(multibyte, ((StringItem *) current)->str.ptr, len * 2);
    // parse time from iso8601
    timestamp_t ts;
    if (timestamp_parse(multibyte, multibytes, &ts) != 0)
      fprintf(stdout, "Error parsing date\n");
    
    struct tm        tm;
    memset(&tm, 0, sizeof (struct tm));
    ngx_libc_gmtime(ts.sec, &tm);
    
    
    u_char *p = ngx_palloc(r->pool, 256);
    if (p == NULL) {
        return NULL;
    }
    
    MBStringItem  *ret = ngx_pcalloc(r->pool, sizeof(MBStringItem));
    ret->item.type = UJT_MBString;
    ret->str.cchLen = strftime((char *) p, 255,
                               (char *) "%a %b %e %H:%M %Y\0", &tm);
    ret->str.ptr = p;
    if (ret->str.cchLen != 0) {
      *(p + ret->str.cchLen) = '\0';
      current = (UJObject *) ret;
    }
    
  // parse & format date
  } else if (fn == 4) {
    int len = ((StringItem *) current)->str.cchLen;
    char multibyte[len * 2];
    int multibytes = wcstombs(multibyte, ((StringItem *) current)->str.ptr, len * 2);

    // parse time from iso8601
    timestamp_t ts;
    timestamp_parse(multibyte, multibytes, &ts);
    ngx_tm_t tm;
    ngx_gmtime(ts.sec, &tm);

    u_char *p = ngx_palloc(r->pool, sizeof("yyyy-mm-dd") - 1);
    if (p == NULL) {
        return NULL;
    }

    ngx_sprintf(p, "%04d-%02d-%02d", tm.ngx_tm_year, tm.ngx_tm_mon,
                tm.ngx_tm_mday);

    MBStringItem  *ret = ngx_pcalloc(r->pool, sizeof(MBStringItem));
    ret->item.type = UJT_MBString;
    ret->str.ptr = p;
    ret->str.cchLen = sizeof("yyyy-mm-dd") - 1;;

    current = (UJObject *) ret;   
  }
  switch (((Item *) current)->type) {
    case UJT_String:
      if (((StringItem *) current)->str.cchLen == 0)
        return NULL;
      break;
    case UJT_MBString:
      if (((MBStringItem *) current)->str.cchLen == 0)
        return NULL;
      break;
    case UJT_Array: case UJT_Object:
      if (!((ObjectItem *) current)->head)
        return NULL;
      break;
      if (!((ObjectItem *) current)->head)
        return NULL;
      break;
    case UJT_Null:
      return NULL;
  }
  return current;
}
