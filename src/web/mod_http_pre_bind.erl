%%%----------------------------------------------------------------------
%%% File    : mod_http_pre_bind.erl
%%% Author  : Nathan Zorn <nathan@collecta.com>
%%% Purpose : Pre-Bind BOSH session over http
%%%----------------------------------------------------------------------

%%%----------------------------------------------------------------------
%%% this module acts as a bridge to ejabberd_http_pre_bind which implements
%%% the real stuff
%%%----------------------------------------------------------------------

-module(mod_http_pre_bind).
-author('nathan@collecta.com').

-behaviour(gen_mod).

-export([
    start/2,
    stop/1,
    process/2
  ]).

-include_lib("exmpp/include/exmpp.hrl").

-include("ejabberd_http_pre_bind.hrl").
-include("ejabberd.hrl").
-include("ejabberd_http.hrl").
-include("http_bind.hrl").

%%%----------------------------------------------------------------------
%%% API
%%%----------------------------------------------------------------------

process([], #request{method = 'POST',
    data = []}) ->
  ?DEBUG("Bad Request: no data", []),
  ?MOD_HTTP_PRE_BIND_BAD_REQUEST;

process([], #request{method = 'POST',
    data = Data,
    ip = IP}) ->
  ?DEBUG("Incoming data: ~s", [Data]),
  ejabberd_http_pre_bind:process_request(Data, IP);

process([], #request{method = 'GET',
                     data = []}) ->
    {200, ?HEADER, get_human_html_xmlel()};
process([], #request{method = 'OPTIONS',
                     data = []}) ->
    {200, ?OPTIONS_HEADER, []};
process(_Path, _Request) ->
    ?DEBUG("Bad Request: ~p", [_Request]),
    {400, ?HEADER, {xmlelement, "h1", [],
           [{xmlcdata, "400 Bad Request"}]}}.

get_human_html_xmlel() ->
  ?DEBUG("Returning HTML", []),
  Heading = "Ejabberd " ++ atom_to_list(?MODULE) ++ " v" ++ ?MOD_HTTP_PRE_BIND_VERSION,
    #xmlel{name = html, attrs = [#xmlattr{name = <<"xmlns">>, value = <<"http://www.w3.org/1999/xhtml">>}], children = [
        #xmlel{name = head, children = [
            #xmlel{name = title, children = [
                #xmlcdata{cdata = Heading}
              ]
            }
          ]
        },
        #xmlel{name = body, children = [
            #xmlel{name = body, children = [
                #xmlel{name = h1, children = [
                    #xmlcdata{cdata = Heading}
                  ]
                },
                #xmlel{name = p, children = [
                    #xmlcdata{cdata = <<"An implementation of ">>},
                    #xmlel{name = a, attrs = [#xmlattr{name = <<"href">>, value = <<"http://www.xmpp.org/extensions/xep-0206.html">>}], children = [
                        #xmlcdata{cdata = <<"Pre-Bind XMPP over BOSH (XEP-0206)">>}
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }
      ]
    }.


%%%----------------------------------------------------------------------
%%% BEHAVIOUR CALLBACKS
%%%----------------------------------------------------------------------
start(_Host, _Opts) ->
  HTTPBindSupervisor =
  {ejabberd_http_pre_bind_sup,
    {ejabberd_tmp_sup, start_link,
      [ejabberd_http_pre_bind_sup, ejabberd_http_pre_bind]},
    permanent,
    infinity,
    supervisor,
    [ejabberd_tmp_sup]},
  case supervisor:start_child(ejabberd_sup, HTTPBindSupervisor) of
    {ok, _Pid} ->
      ok;
    {ok, _Pid, _Info} ->
      ok;
    {error, {already_started, _PidOther}} ->
      % mod_http_pre_bind is already started so it will not be started again
      ok;
    {error, Error} ->
      {'EXIT', {start_child_error, Error}}
  end.

stop(_Host) ->
  case supervisor:terminate_child(ejabberd_sup, ejabberd_http_pre_bind_sup) of
    ok ->
      ok;
    {error, Error} ->
      {'EXIT', {terminate_child_error, Error}}
  end.

