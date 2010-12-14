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

%% Entry point for data coming from client through ejabberd HTTP server
process_request(Data, IP) ->
  %% Parse incoming data.
  {ok, {Rid, Jid, XmppDomain, Attrs}} = parse_request(Data),

  %% Start the cycle
  Sid = ejabberd_http_bind:make_sid(),
  start_http_bind(Sid, IP, Rid, XmppDomain, Attrs),

  %% Authenticate, depending on if from is 'anonymous' or an actual Jid.
  %% If the message is from "anonymous", SASL Anonymous is used, otherwise SASL Plain.
  RidA = start_auth(Sid, IP, Rid + 1, Jid),

  %% Start the XMPP Stream.
  RidB = start_stream(Sid, IP, RidA + 1, XmppDomain),

  %% Bind to the Stream.
  RidC = start_bind(Sid, IP, RidB + 1),

  %% Start the XMPP Session.
  {RidD, Retval} = start_session(Sid, IP, RidC + 1),
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

%% <body rid='186930086' xmlns='http://jabber.org/protocol/httpbind' to='example.com' xml:lang='en' wait='60' hold='1' content='text/xml; charset=utf-8' ver='1.6' xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh'/>
start_http_bind(Sid, IP, Rid, XmppDomain, Attrs) ->
  ?DEBUG("Start HTTP Bind", []),
  {ok, Pid} = ejabberd_http_bind:start(XmppDomain, Sid, "", IP),
  StartAttrsXml = [
    exmpp_xml:attribute(<<"rid">>, Rid),
    exmpp_xml:attribute(<<"to">>, XmppDomain),
    exmpp_xml:attribute(?NS_XML, <<"lang">>, <<"en">>),
    exmpp_xml:attribute(<<"content">>, <<"text/xml; charset=utf-8">>),
    exmpp_xml:attribute(<<"ver">>, <<"1.6">>),
    exmpp_xml:attribute(?NS_BOSH, <<"version">>, <<"1.0">>)
  ],
  AttrsXml = lists:map(fun(X) -> {Key, Val} = X, Bkey = list_to_binary(Key), Bval = list_to_binary(Val), exmpp_xml:attribute(Bkey, Bval) end, Attrs),
  StartAttrs = lists:append(StartAttrsXml, AttrsXml),
  ejabberd_http_bind:handle_session_start(Pid, XmppDomain, Sid, Rid, StartAttrs, [], 0, IP).

%% <body rid='186930087' xmlns='http://jabber.org/protocol/httpbind' sid='9d0343aed0c0398a615220b74973659ccfa54a4c-55238004'><auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='ANONYMOUS'/></body>
start_auth(Sid, IP, Rid, Jid) ->
  ?DEBUG("Start Auth", []),
  Attrs = [
    exmpp_xml:attribute(<<"rid">>, Rid),
    exmpp_xml:attribute(<<"sid">>, Sid) %% Sid is already a binary
  ],
  Mechanism = auth_mechanism(Jid),
  Payload = [exmpp_client_sasl:selected_mechanism(Mechanism)],
  RidA = handle_auth(Sid, Rid, Attrs, Payload, 0, false, IP, 0),
  RidA.
  
auth_mechanism(Jid) ->
  case Jid of
    "anonymous" ->
      "ANONYMOUS";
    _ ->
      "PLAIN"
  end.

handle_auth(_Sid, Rid, _Attrs, _Payload, _PayloadSize, _StreamStart, _IP, ?MAX_COUNT) ->
  Rid;

handle_auth(Sid, Rid, Attrs, Payload, PayloadSize, StreamStart, IP, Count) ->
  case handle_http_put(Sid, Rid, Attrs, Payload, PayloadSize, StreamStart, IP) of
    {ok, [#xmlstreamelement{element = #xmlel{name = success}}]} ->
      ?DEBUG("Success authenticating", []),
      Rid;
    {ok, _Els} ->
      ?DEBUG("Authentication failed, sleeping", []),
      timer:sleep(100),
      handle_auth(Sid, Rid + 1, Attrs, Payload, PayloadSize, StreamStart, IP, Count + 1);
    _ ->
      ?DEBUG("Authentication failed, falling through", []),
      Rid
  end.

%% <body rid='186930088' xmlns='http://jabber.org/protocol/httpbind' sid='9d0343aed0c0398a615220b74973659ccfa54a4c-55238004' to='example.com' xml:lang='en' xmpp:restart='true' xmlns:xmpp='urn:xmpp:xbosh'/>
start_stream(Sid, IP, Rid, XmppDomain) ->
  ?DEBUG("Start stream", []),
  Attrs = [
    exmpp_xml:attribute(<<"rid">>, Rid),
    exmpp_xml:attribute(<<"sid">>, Sid), %% Sid is already a binary
    exmpp_xml:attribute(<<"to">>, XmppDomain), %% XmppDomain is already a binary
    exmpp_xml:attribute(?NS_XML, <<"lang">>, <<"en">>),
    exmpp_xml:attribute(?NS_BOSH, <<"restart">>, <<"true">>)
  ],
  handle_http_put(Sid, Rid, Attrs, [], 0, true, IP),
  Rid + 1.

start_bind(Sid, IP, Rid) ->
  ?DEBUG("Start bind", []),
  Attrs = [
    exmpp_xml:attribute(<<"rid">>, Rid),
    exmpp_xml:attribute(<<"sid">>, Sid), %% Already a binary
    exmpp_xml:attribute(<<"xmlns">>, ?NS_HTTP_BIND_b)
  ],
  %% <body rid='186930089' xmlns='http://jabber.org/protocol/httpbind' sid='9d0343aed0c0398a615220b74973659ccfa54a4c-55238004'><iq type='set' id='_bind_auth_2' xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></iq></body>
  Payload = [exmpp_client_binding:bind()],
  RidC = handle_bind(Sid, Rid, Attrs, Payload, 0, false, IP, 0),
  RidC.

handle_bind(_Sid, Rid, _Attrs, _Payload, _PayloadSize, _StreamStart, _IP, ?MAX_COUNT) ->
  Rid;

handle_bind(Sid, Rid, Attrs, Payload, PayloadSize, StreamStart, IP, Count) ->
  case handle_http_put(Sid, Rid, Attrs, Payload, PayloadSize, StreamStart, IP) of
    {ok, [#xmlstreamelement{element = #xmlel{name = iq}}]} ->
      ?DEBUG("Success binding", []),
      Rid;
    {ok, _Els} ->
      ?DEBUG("Bind failed, sleeping", []),
      timer:sleep(100),
      handle_bind(Sid, Rid + 1, Attrs, Payload, PayloadSize, StreamStart, IP, Count + 1);
    _ ->
      ?DEBUG("Bind failed, falling through", []),
      Rid
  end.

start_session(Sid, IP, Rid) ->
  ?DEBUG("Start session", []),
  Attrs = [
    exmpp_xml:attribute(<<"rid">>, Rid),
    exmpp_xml:attribute(<<"sid">>, Sid), %% Sid is already a binary
    exmpp_xml:attribute(<<"xmlns">>, ?NS_HTTP_BIND_b)
  ],
  Payload = [exmpp_client_session:establish()],
  {RidD, Response} = handle_session(Sid, Rid, Attrs, Payload, 0, false, IP, 0),
  {RidD, Response}.

handle_session(_Sid, Rid, _Attrs, _Payload, _PayloadSize, _StreamStart, _IP, ?MAX_COUNT) ->
  Rid;

handle_session(Sid, Rid, Attrs, Payload, PayloadSize, StreamStart, IP, Count) ->
  case handle_http_put(Sid, Rid, Attrs, Payload, 0, false, IP) of
    {ok, [#xmlstreamelement{element = #xmlel{name = iq}}]} ->
      ?DEBUG("Success streaming", []),
      Rid;
    {ok, _Els} ->
      ?DEBUG("Session failed, sleeping", []),
      timer:sleep(100),
      handle_session(Sid, Rid + 1, Attrs, Payload, PayloadSize, StreamStart, IP, Count + 1);
    _ ->
      ?DEBUG("Session failed, falling through", []),
      Rid
  end.

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

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.
