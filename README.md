# Mustache nginx module

A module that renders mustache templates in nginx on endpoints that output json. It has support for layouts (header and footer), and for additional source of variables (as json in `$meta` nginx variable). 

Mustache module is compatible with json output of forked ngx_postgres module, but also should work with static files and upstream responses. 

It uses ujson4c (ultrajson wrapper) and mustache.c. 

**Warning**: It's written in a fairly amateurish style, as it's my first C project. Please don't expect the same quality of C code as the rest of nginx modules around. Not all codepaths are failsafe at this point.

**Not production ready**, but I gladly would accept help to get it there.

## Weird flavour of mustache

Mustache usually means templates without logic. But it supports looping arrays, positive and negative conditions. 
If json is array, template is rendered multiple time for each array item.

Our flavour of mustache has a few features:

* `parent:` and `parent::` prefixes in variables to access parent scopes in nested sections
* `meta:` prefix to access json values stored in $meta variable of nginx request
* Outputs html escaped, but allows raw via `:HTML` suffix
* Provides simple way to access dynamic key: `this[variable]` in javascript becomes `by:variable`
* Simple string equality matching with `:is:...` suffix

### Example of a template


    // example.json
    {
      people: [
        {
          name: "Boris", 
          items: [{
            title: "godzilla"
          }]
        },
        {
          name: "Max", 
          items: [{
            title: "cupholder"
          }]
        }
      ]
    }


    // example.html
    
    {{^people}}
      <h2>There are no people</h2>
    {{/people}}

    {{#people}}
      {{#items}}
        {{#title:is:godzilla}}
          This item is godzilla, owned by {{parent:name}}
        {{/title:is:godzilla}}
        {{^title:is:godzilla}}
          This item name is {{title}}, owned by {{parent:name}}
        {{/title:is:godzilla}}
      {{/items}}
    {{/people}}


## Example 1: No dependencies, static json

Set up `$views` to the directory which holds your templates. If response body is json, mustache module will parse it and render with template specified in `$html` variable. Final HTML may be wrapped with header and footer files set in `$before` and `$after` variables.


    server {
      ...
      set $views "/Users/invizko/sites/data/views/";

      set $before "header.html";
      set $html   "";            # redefine this variable in request
      set $after  "footer.html";

      location /example.json {
        mustache on;
        set $html "template.html"
      }
    }


## Example 2: Preflight json request

Json provided in `$meta` variable will be accessible in template with `{{meta:...}}` prefix. Using eval nginx module you can make preflight request like checking user authentication and role. See ngx_postgres readme for some examples of that.


    server {
      ...
      set $views "/Users/invizko/sites/data/views/";
      set $before "header.html";
      set $html   "";            # redefine this variable in request
      set $after  "footer.html";

      location /example.json {
        eval $meta {
          rewrite ^ /meta.json
        }
        set $html "template.html"
      }
    }


## Example 3: Restful mustache with forked ngx_postgres
  
With our fork of ngx you can render templates conditionally on method, number of rows or even validation status. 

    
    location /(?<resources>[^/]+)/(?<id>)/$ {

      postgres_query   GET "SELECT * FROM $resource WHERE id = :id";
      postgres_rewrite GET rows    fields.html;
      postgres_rewrite GET no_rows 404;

      postgres_query   DELETE "DELETE from $resource where id = :id";
      postgres_rewrite DELETE changes    /$resource/;
      postgres_rewrite DELETE no_changes 404;

      postgres_query   POST PUT  "UPDATE $resources SET ...";
      postgres_rewrite POST PUT errors    fields.html;
      postgres_rewrite POST PUT no_errors /$resource/:id/?flash=:success;
    }
