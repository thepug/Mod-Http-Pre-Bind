%%%----------------------------------------------------------------------
%%% File    : ejabberd_http_pre_bind.hrl
%%% Author  : W. Andrew Loe III <andrew@andrewloe.com>
%%% Purpose : Shared Macros
%%%----------------------------------------------------------------------

-define(MOD_HTTP_PRE_BIND_VERSION, "0.2").
-define(MOD_HTTP_PRE_BIND_BAD_REQUEST, {400, ?HEADER,
    #xmlel{name = <<"h1">>, children = [
        {xmlcdata, <<"400 Bad Request">>}
      ]
    }
  }).

-define(NS_HTTP_BIND,
    <<"http://jabber.org/protocol/httpbind">>).
