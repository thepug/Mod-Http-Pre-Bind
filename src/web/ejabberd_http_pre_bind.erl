%%%----------------------------------------------------------------------
%%% File    : ejabberd_http_pre_bind.erl
%%% Author  : Nathan Zorn <nathan@collecta.com>
%%% Purpose : Implements Pre-Bind XMPP over BOSH (XEP-0205) 
%%%----------------------------------------------------------------------

-module(ejabberd_http_pre_bind).

%% External exports
-export([code_change/3,
    process_request/2]).

-include_lib("exmpp/include/exmpp.hrl").

-include("ejabberd_http_pre_bind.hrl").
-include("ejabberd.hrl").
-include("ejabberd_http.hrl").

-define(HEADER, [{"Content-Type", "text/xml; charset=utf-8"}, 
    {"Access-Control-Allow-Origin", "*"}, 
    {"Access-Control-Allow-Headers", "Content-Type"}]).

-define(MAX_COUNT, 3).

%% handle http put similar to bind, but withouth send_outpacket
handle_http_put(Sid, Rid, Attrs, Payload, PayloadSize, StreamStart, IP) ->
  case ejabberd_http_bind:http_put(Sid, Rid, Attrs, Payload, PayloadSize, StreamStart, IP) of
    {error, not_exists} ->
      ?DEBUG("no session associated with sid: ~p", [Sid]),
      {error, not_exists};
    {{error, Reason}, _Sess} ->
      ?DEBUG("Error on HTTP put. Reason: ~p", [Reason]),
      %% ignore errors
      {ok, []};
    {{wait, Pause}, _Sess} ->
      ?DEBUG("Trafic Shaper: Delaying request ~p", [Rid]),
      timer:sleep(Pause),
      handle_http_put(Sid, Rid, Attrs, Payload, PayloadSize,
        StreamStart, IP);
    {buffered, _Sess} ->
      ?DEBUG("buffered", []),
      {ok, []};
    {ok, Sess} ->
      handle_response(Sess, Rid);
    Out ->
      ?ERROR_MSG("Handle Put was invalid : ~p ~n", [Out]),
      {error, undefined}
  end.

handle_response(Sess, Rid) ->
  ?DEBUG("Handling response.", []),
  case catch ejabberd_http_bind:http_get(Sess, Rid) of
    {ok, cancel} ->
      {ok, cancel};
    {ok, empty} ->
      {ok, empty};
    {ok, terminate} ->
      {ok, terminate};
    {ok, ROutPacket} ->
      OutPacket = lists:reverse(ROutPacket),
      ?DEBUG("OutPacket: ~p", [OutPacket]),
      {ok, OutPacket};
    {'EXIT', {shutdown, _}} ->
      {error, terminate};
    {'EXIT', _Reason} ->
      {error, terminate}
  end.

handle_auth(_Sid, Rid, 
  _Attrs, _Payload, 
  _PayloadSize, 
  _StreamStart, 
  _IP, ?MAX_COUNT) ->
  Rid;

handle_auth(Sid, Rid, 
  Attrs, Payload, 
  PayloadSize, 
  StreamStart, 
  IP, Count) ->
  %% wait to make sure we had auth success.
  case handle_http_put(Sid, Rid, Attrs, 
      Payload, PayloadSize, 
      StreamStart, IP) of
    {ok, [{xmlstreamelement,
          {xmlelement,"success",
            [{"xmlns","urn:ietf:params:xml:ns:xmpp-sasl"}],
            []}}]} ->
      Rid;
    {ok, _Els} ->
      timer:sleep(100),
      handle_auth(Sid, Rid + 1, Attrs, Payload, 
        PayloadSize, StreamStart, IP, Count + 1);
    _ ->
      Rid
  end.

handle_bind(_, Rid, _, ?MAX_COUNT) ->
  {Rid, {200,
      [{"Content-Type","text/xml; charset=utf-8"}],
      []}};

handle_bind(Sid, Rid, IP, Count) ->
  BindAttrs = [
    {"rid",integer_to_list(Rid)},
    {"xmlns",?NS_HTTP_BIND},
    {"sid",Sid}],
  BindPayload = [{xmlelement,"iq",
      [{"type","set"},
        {"id","_bind_auth_2"},
        {"xmlns","jabber:client"}],
      [{xmlelement,"bind",
          [{"xmlns",
              "urn:ietf:params:xml:ns:xmpp-bind"}],[]}]}],
  BindPayloadSize = 228,
  {ok, Retval0} = handle_http_put(Sid,
    Rid,
    BindAttrs,
    BindPayload,
    BindPayloadSize,
    false,
    IP),
  ?DEBUG("Retval ~p ~n",[Retval0]),
  Els = [OEl || {xmlstreamelement, OEl} <- Retval0],
  case lists:any(fun({xmlelement, "iq", _, _}) ->
          true;
        (_) ->
          false
      end, Els) of 
    true ->
      XmlElementString = xml:element_to_string({xmlelement,"body",
          [{"xmlns",
              ?NS_HTTP_BIND}] ++ 
          [{"sid",Sid}] ++ 
          [{"rid",integer_to_list(Rid+1)}],
          Els}),
      {Rid, {200,
          [{"Content-Type","text/xml; charset=utf-8"}],
          XmlElementString}};
    false ->
      handle_bind(Sid, Rid + 1, IP, Count + 1)
  end.

%% Entry point for data coming from client through ejabberd HTTP server
process_request(Data, IP) ->
  %% Parse incoming data.
  {ok, {Rid, Jid, XmppDomain, Attrs}} = parse_request(Data),

  %% Start a session
  Sid = ejabberd_http_bind:make_sid(),
  start_http_bind(Sid, IP, Rid, XmppDomain, Attrs),

  %% Authenticate, depending on if from is 'anonymous' or an actual Jid.
  %% If the message is from "anonymous", SASL Anonymous is used, otherwise SASL Plain.
  RidA = start_auth(Sid, IP, Rid + 1, Jid),

  %% Start the XMPP Stream.
  {RidB, Retval} = start_stream(Sid, IP, RidA + 1, XmppDomain),

  %% Start the XMPP Session.
  start_session(Sid, IP, RidB + 1),

  Retval.

%% Parse the initial client request to start the pre bind session.
parse_request(Data) ->
  case exmpp_xmlstream:parse_element(Data) of
    [#xmlel{name = body, attrs = Attrs, children = _Children}] ->
      case catch list_to_integer(exmpp_xml:get_attribute_from_list_as_list(Attrs, <<"rid">>, error)) of
        {'EXIT', Reason} ->
          ?ERROR_MSG("error in body ~p",[Reason]),
          ?MOD_HTTP_PRE_BIND_BAD_REQUEST;
        Rid ->
          Jid = exmpp_xml:get_attribute_from_list_as_list(Attrs, <<"from">>, error),
          XmppDomain = exmpp_xml:get_attribute_from_list_as_list(Attrs, <<"to">>, error),
          RetAttrs = [
            {"wait", exmpp_xml:get_attribute_from_list_as_list(Attrs, <<"wait">>, error)},
            {"hold", exmpp_xml:get_attribute_from_list_as_list(Attrs, <<"hold">>, error)}
          ],
          {ok, {Rid, Jid, XmppDomain, RetAttrs}}
      end;
    [#xmlel{name = Name, attrs = _Attrs, children = _Children}] ->
      ?ERROR_MSG("Not a body ~p",[Name]),
      ?MOD_HTTP_PRE_BIND_BAD_REQUEST;
    _ ->
      ?ERROR_MSG("Error with parse.",[]),
      ?MOD_HTTP_PRE_BIND_BAD_REQUEST
  end.

start_http_bind(Sid, IP, Rid, XmppDomain, Attrs) ->
  ?DEBUG("start_http_bind, Rid: ~p", [Rid]),
  {ok, Pid} = ejabberd_http_bind:start(XmppDomain, Sid, "", IP),
  StartAttrs = [
    {"rid", Rid},
    {"to", XmppDomain},
    {"xmlns", ?NS_HTTP_BIND},
    {"xml:lang", "en"},
    {"xmpp:version", "1.0"},
    {"ver", "1.6"},
    {"xmlns:xmpp", "urn:xmpp:bosh"},
    {"window", "5"},
    {"content", "text/xml"},
    {"charset", "utf-8"}
  ],
  StartAttrsL = lists:append(StartAttrs, Attrs),
  ejabberd_http_bind:handle_session_start(Pid, XmppDomain, Sid, Rid, StartAttrsL, [], 0, IP).

start_auth(Sid, IP, Rid, Jid) ->
  ?DEBUG("start_auth Rid: ~p", [Rid]),
  Attrs = {ok , [
      {"rid", integer_to_list(Rid)},
      {"xmlns", ?NS_HTTP_BIND},
      {"sid", Sid}
    ]},
  Payload = #xmlel{name = <<"auth">>, attrs = [
        #xmlattr{name = <<"xmlns">>, value = <<"urn:ietf:params:xml:ns:xmpp-sasl">>},
        #xmlattr{name = <<"mechanism">>, value = list_to_binary(auth_mechanism(Jid))}
      ]},
  RidA = handle_auth(Sid, Rid, Attrs, Payload, 0, false, IP, 0),
  RidA.
  
auth_mechanism(Jid) ->
  case Jid of
    "anonymous" ->
      "ANONYMOUS";
    _ ->
      "PLAIN"
  end.

start_stream(Sid, IP, Rid, XmppDomain) ->
  Attrs = [
    {"rid", integer_to_list(Rid)},
    {"sid", Sid},
    {"xmlns", ?NS_HTTP_BIND},
    {"xml:lang", "en"},
    {"xmlns:xmpp", "urn:xmpp:xbosh"},
    {"to", XmppDomain},
    {"xmpp:restart", "true"}
  ],
  handle_http_put(Sid, Rid, Attrs, [], 0, true, IP),
  {RidB, Retval} = handle_bind(Sid, Rid + 1, IP, 0),
  {RidB, Retval}.

start_session(Sid, IP, Rid) ->
  Attrs = [
    {"rid", integer_to_list(Rid)},
    {"xmlns", ?NS_HTTP_BIND},
    {"sid", Sid}
  ],
 Payload = [{xmlelement,"iq",
      [{"type","set"},
        {"id","_session_auth_2"},
        {"xmlns","jabber:client"}],
      [{xmlelement,"session",
          [{"xmlns",
              "urn:ietf:params:xml:ns:xmpp-session"}],[]}]}],
  PayloadSize = iolist_size(Payload),
  handle_http_put(Sid, Rid, Attrs, Payload, PayloadSize, false, IP).

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.
