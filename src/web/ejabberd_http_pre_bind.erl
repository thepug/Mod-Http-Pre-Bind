%%%----------------------------------------------------------------------
%%% File    : ejabberd_http_pre_bind.erl
%%% Authors : Nathan Zorn <nathan@collecta.com>, W. Andrew Loe III <loe@onehub.com>
%%% Purpose : Implements Pre-Bind XMPP over BOSH (XEP-0205)
%%%----------------------------------------------------------------------

-module(ejabberd_http_pre_bind).

-export([process_request/2]).

-include("jlib.hrl").

-include("ejabberd_http_pre_bind.hrl").
-include("ejabberd.hrl").
-include("ejabberd_http.hrl").
-include("http_bind.hrl").
-include("logger.hrl").

-define(MAX_COUNT, 3).

%% Entry point for data coming from client through ejabberd HTTP server
process_request(Data, IP) ->
  %% Parse incoming data.
  {ok, {Rid, From, Password, XmppDomain, Attrs}} = parse_request(Data),

  %% Start the cycle
  Sid = sha:sha(term_to_binary({now(), make_ref()})),
  RidA = start_http_bind(Sid, IP, Rid, From, XmppDomain, Attrs),

  %% If From is empty or set to Anonymous, SASL Anonymous is used.
  RidB = start_auth(Sid, IP, RidA + 1, From, Password),

  %% Restart the XMPP Stream.
  RidC = restart_stream(Sid, IP, RidB + 1, XmppDomain),

  %% Bind to the Stream.
  {RidD, BindResponse} = start_bind(Sid, IP, RidC + 1),

  %% Start the XMPP Session.
  RidE = start_session(Sid, IP, RidD + 1),

  [{xmlstreamelement, IQ}] = BindResponse,

  Body = #xmlel{name = <<"body">>, attrs = [
      {<<"xmlns">>, ?NS_HTTP_BIND},
      {<<"rid">>, jlib:integer_to_binary(RidE + 1)},
      {<<"sid">>, Sid}
    ], children = [IQ]},

  ?DEBUG("Body: ~p", [Body]),
  {200, ?HEADER, Body}.

%% Parse the initial client request to start the Pre-Bind process.
parse_request(Data) ->
  case xml_stream:parse_element(Data) of
    #xmlel{name = <<"body">>, attrs = Attrs, children = _Children} ->
      case catch jlib:binary_to_integer(xml:get_attr_s(<<"rid">>, Attrs)) of
        {'EXIT', Reason} ->
          ?ERROR_MSG("error in body ~p",[Reason]),
          ?MOD_HTTP_PRE_BIND_BAD_REQUEST;
        Rid ->
          From = xml:get_attr_s(<<"from">>, Attrs),
          Password = xml:get_attr_s(<<"password">>, Attrs),
          XmppDomain = xml:get_attr_s(<<"to">>, Attrs),
          RetAttrs = [
            {<<"wait">>, xml:get_attr_s(<<"wait">>, Attrs)},
            {<<"hold">>, xml:get_attr_s(<<"hold">>, Attrs)}
          ],
          {ok, {Rid, From, Password, XmppDomain, RetAttrs}}
      end;
    #xmlel{name = Name, attrs = _Attrs, children = _Children} ->
      ?ERROR_MSG("Not a body ~p",[Name]),
      ?MOD_HTTP_PRE_BIND_BAD_REQUEST;
    _ ->
      ?ERROR_MSG("Error with parse.",[]),
      ?MOD_HTTP_PRE_BIND_BAD_REQUEST
  end.

%%<body content='text/xml; charset=utf-8'
%%      from='user@example.com'
%%      hold='1'
%%      rid='1573741820'
%%      to='example.com'
%%      route='xmpp:example.com:9999'
%%      secure='true'
%%      wait='60'
%%      xml:lang='en'
%%      xmpp:version='1.0'
%%      xmlns='http://jabber.org/protocol/httpbind'
%%      xmlns:xmpp='urn:xmpp:xbosh'/>
start_http_bind(Sid, IP, Rid, From, XmppDomain, Attrs) ->
  ?DEBUG("HTTP Bind Start", []),
  {ok, Pid} = ejabberd_http_bind:start(XmppDomain, Sid, <<"">>, IP),
  StartAttrsXml = [
    {<<"rid">>, Rid},
    {<<"to">>, XmppDomain},
    {<<"from">>, From},
    {<<"xml", ":", "lang">>, <<"en">>},
    {<<"content">>, <<"text/xml; charset=utf-8">>},
    {<<"ver">>, <<"1.6">>},
    {<<"xmpp", ":", "version">>, <<"1.0">>},
    {<<"xmlns">>, ?NS_HTTP_BIND}
  ],
  AttrsXml = Attrs,
  FullAttrs = lists:append(StartAttrsXml, AttrsXml),
  %% handle_session_start does some internal consistentcy checkes, then passes to handle_http_put
  Rid = handle_http_bind(Pid, XmppDomain, Sid, Rid, FullAttrs, [], 0, IP, 0),
  Rid.

%%<body wait='60'
%%      inactivity='30'
%%      polling='5'
%%      requests='2'
%%      hold='1'
%%      from='example.com'
%%      accept='deflate,gzip'
%%      sid='SomeSID'
%%      secure='true'
%%      charsets='ISO_8859-1 ISO-2022-JP'
%%      xmpp:restartlogic='true'
%%      xmpp:version='1.0'
%%      authid='ServerStreamID'
%%      xmlns='http://jabber.org/protocol/httpbind'
%%      xmlns:xmpp='urn:xmpp:xbosh'
%%      xmlns:stream='http://etherx.jabber.org/streams'>
%%  <stream:features>
%%    <mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>
%%      <mechanism>SCRAM-SHA-1</mechanism>
%%      <mechanism>PLAIN</mechanism>
%%    </mechanisms>
%%  </stream:features>
%%</body>
handle_http_bind(Pid, XmppDomain, Sid, Rid, Attrs, Payload, PayloadSize, IP, _Count) ->
  case ejabberd_http_bind:handle_session_start(Pid, XmppDomain, Sid, Rid, Attrs, Payload, PayloadSize, IP) of
    {200, _Headers, _Body} ->
      ?DEBUG("HTTP Bind Success", []),
      Rid;
    Response ->
      ?DEBUG("HTTP Bind Failed: ~p", [Response]),
      Rid
  end.

%%<body rid='186930087'
%%      xmlns='http://jabber.org/protocol/httpbind'
%%      sid='9d0343aed0c0398a615220b74973659ccfa54a4c-55238004'>
%%  <auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='ANONYMOUS'/>
%%</body>
%% OR with SASL PLAIN
%%<body rid='186930087'
%%      xmlns='http://jabber.org/protocol/httpbind'
%%      sid='9d0343aed0c0398a615220b74973659ccfa54a4c-55238004'>
%%  <auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>Base64 encoded username/password</auth>
%%</body>

start_auth(Sid, IP, Rid, From, Password) ->
  ?DEBUG("Authentication Start", []),
  Attrs = [
    {<<"rid">>, Rid},
    {<<"sid">>, Sid},
    {<<"xmlns">>, ?NS_HTTP_BIND}
  ],
  Payload = auth_payload(From, Password),
  RidL = handle_auth(Sid, Rid, Attrs, Payload, 0, false, IP, 0),
  RidL.

%% Decide and generate the appropriate SASL response.
auth_payload(From, Password) ->
  Mechanism = case catch jlib:string_to_jid(From) of
    {'EXIT', _Reason} ->
      selected_mechanism(<<"ANONYMOUS">>);
    Jid ->
      InitialResponse = iolist_to_binary([0, jlib:jid_to_string(Jid), 0, Password]),
      selected_mechanism(<<"PLAIN">>, InitialResponse)
  end,
  [Mechanism].

selected_mechanism(Mechanism) ->
    #xmlel{name = <<"auth">>,
           attrs = [
                    {<<"xmlns">>, ?NS_SASL},
                    {<<"mechanism">>, Mechanism}
                   ]
          }.
selected_mechanism(Mechanism, Initial_Response) ->
    El = selected_mechanism(Mechanism),
    El#xmlel{children = [{xmlcdata, base64:encode(Initial_Response)}]}.

%%<body xmlns='http://jabber.org/protocol/httpbind'>
%%  <success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>
%%</body>
handle_auth(_Sid, Rid, _Attrs, _Payload, _PayloadSize, _StreamStart, _IP, ?MAX_COUNT) ->
  ?DEBUG("Authentication Max Poll", []),
  Rid;

handle_auth(Sid, Rid, Attrs, Payload, PayloadSize, StreamStart, IP, Count) ->
  case handle_http_put(Sid, Rid, Attrs, Payload, PayloadSize, StreamStart, IP) of
    {ok, [{xmlstreamelement, #xmlel{name = <<"success">>}}]} ->
      ?DEBUG("Authentication Success", []),
      Rid;
    {ok, Response} ->
      ?DEBUG("Authentication Missed: Polling with blank requests: ~p", [Response]),
      timer:sleep(100),
      handle_auth(Sid, Rid + 1, [], [], 0, StreamStart, IP, Count + 1);
    _ ->
      ?DEBUG("Authentication Failed", []),
      Rid
  end.

%%<body rid='1573741824'
%%      sid='SomeSID'
%%      to='example.com'
%%      xml:lang='en'
%%      xmpp:restart='true'
%%      xmlns='http://jabber.org/protocol/httpbind'
%%      xmlns:xmpp='urn:xmpp:xbosh'/>
restart_stream(Sid, IP, Rid, XmppDomain) ->
  ?DEBUG("Restart Stream Start", []),
  Attrs = [
    {<<"rid">>, Rid},
    {<<"sid">>, Sid},
    {<<"to">>, XmppDomain},
    {<<"xml", ":", "lang">>, <<"en">>},
    {<<"xmpp", ":", "restart">>, <<"true">>},
    {<<"xmlns">>, ?NS_HTTP_BIND}
  ],
  RidL = handle_restart_stream(Sid, Rid, Attrs, [], 0, true, IP, 0),
  RidL.

%%<body xmlns='http://jabber.org/protocol/httpbind'
%%      xmlns:stream='http://etherx.jabber.org/streams'>
%%  <stream:features>
%%    <bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>
%%  </stream:features>
%%</body>
%% This will typically miss on the first request, because it is looking for the features.
handle_restart_stream(_Sid, Rid, _Attrs, _Payload, _PayloadSize, _StreamStart, _IP, ?MAX_COUNT) ->
  ?DEBUG("Restart Stream Max Poll", []),
  Rid;

handle_restart_stream(Sid, Rid, Attrs, Payload, PayloadSize, StreamStart, IP, Count) ->
  case handle_http_put(Sid, Rid, Attrs, Payload, PayloadSize, StreamStart, IP) of
    {ok, [{xmlstreamelement, #xmlel{name = <<"stream:features">>}}]} ->
      ?DEBUG("Restart Stream Success", []),
      Rid;
    {ok, Response} ->
      ?DEBUG("Restart Stream Missed: Polling with blank requests: ~p", [Response]),
      timer:sleep(100),
      handle_restart_stream(Sid, Rid + 1, [], [], 0, false, IP, Count + 1);
    _ ->
      ?DEBUG("Restart Stream Failed", []),
      Rid
  end.

%%<body rid='1573741825'
%%      sid='SomeSID'
%%      xmlns='http://jabber.org/protocol/httpbind'>
%%  <iq id='bind_1'
%%      type='set'
%%      xmlns='jabber:client'>
%%    <bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>
%%      <resource>httpclient</resource>
%%    </bind>
%%  </iq>
%%</body>
start_bind(Sid, IP, Rid) ->
  ?DEBUG("Bind Start", []),
  Attrs = [
    {<<"rid">>, Rid},
    {<<"sid">>, Sid},
    {<<"xmlns">>, ?NS_HTTP_BIND}
  ],
  Payload = [#xmlel{
        name = <<"iq">>,
        attrs = [
            {<<"type">>, <<"set">>},
            {<<"id">>, <<"bind_1">>},
            {<<"xmlns">>, <<"jabber:client">>}
        ],
        children = [
            #xmlel{
                name = <<"bind">>,
                attrs = [
                    {<<"xmlns">>, <<"urn:ietf:params:xml:ns:xmpp-bind">>}
                ],
                children = [
%% TODO: return clever resource name
%%                     #xmlel{name = <<"resource">>,
%%                         children = [{xmlcdata, <<"httpclient">>}]
%%                     }
                ]
            }
        ]
    }],
  RidL = handle_bind(Sid, Rid, Attrs, Payload, 0, false, IP, 0),
  RidL.

%%<body xmlns='http://jabber.org/protocol/httpbind'>
%%  <iq id='bind_1'
%%      type='result'
%%      xmlns='jabber:client'>
%%    <bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>
%%      <jid>user@example.com/httpclient</jid>
%%    </bind>
%%  </iq>
%%</body>
%% TODO: Extract the provided JID from the Response
handle_bind(_Sid, Rid, _Attrs, _Payload, _PayloadSize, _StreamStart, _IP, ?MAX_COUNT) ->
  ?DEBUG("Bind Max Poll", []),
  {Rid, []};

handle_bind(Sid, Rid, Attrs, Payload, PayloadSize, StreamStart, IP, Count) ->
  R = handle_http_put(Sid, Rid, Attrs, Payload, PayloadSize, StreamStart, IP),
  case R of
    {ok, [{xmlstreamelement, #xmlel{name = <<"iq">>}}]} ->
      ?DEBUG("Bind Success", []),
      {_Status, Body} = R,
      {Rid, Body};
    {ok, Response} ->
      ?DEBUG("Bind Missed: Polling with blank requests: ~p", [Response]),
      timer:sleep(100),
      handle_bind(Sid, Rid + 1, [], [], 0, StreamStart, IP, Count + 1);
    _ ->
      ?DEBUG("Bind Failed", []),
      {Rid, []}
  end.

%%<body rid='186930090'
%%      xmlns='http://jabber.org/protocol/httpbind'
%%      sid='9d0343aed0c0398a615220b74973659ccfa54a4c-55238004'>
%%  <iq type='set'
%%      id='_session_auth_2'
%%      xmlns='jabber:client'>
%%    <session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>
%%  </iq>
%%</body>
start_session(Sid, IP, Rid) ->
  ?DEBUG("Start Session", []),
  Attrs = [
    {<<"rid">>, Rid},
    {<<"sid">>, Sid},
    {<<"xmlns">>, ?NS_HTTP_BIND}
  ],
  Payload = [#xmlel{
        name = <<"iq">>,
        attrs = [
            {<<"type">>, <<"set">>},
            {<<"id">>, <<"_session_auth_2">>},
            {<<"xmlns">>, <<"jabber:client">>}
        ],
        children = [
            #xmlel{
                name = <<"session">>,
                attrs = [
                    {<<"xmlns">>, <<"urn:ietf:params:xml:ns:xmpp-session">>}
                ]
            }
        ]
    }],
  RidL = handle_session(Sid, Rid, Attrs, Payload, 0, false, IP, 0),
  RidL.

%%<body xmlns='http://jabber.org/protocol/httpbind'>
%%  <iq xmlns="jabber:client"
%%      type="result"
%%      id="_session_auth_2"/>
%%</body>
handle_session(_Sid, Rid, _Attrs, _Payload, _PayloadSize, _StreamStart, _IP, ?MAX_COUNT) ->
  ?DEBUG("Session Max Poll", []),
  Rid;

handle_session(Sid, Rid, Attrs, Payload, PayloadSize, StreamStart, IP, Count) ->
  case handle_http_put(Sid, Rid, Attrs, Payload, PayloadSize, StreamStart, IP) of
    {ok, [{xmlstreamelement, #xmlel{name = <<"iq">>}}]} ->
      ?DEBUG("Session Success", []),
      Rid;
    {ok, Response} ->
      ?DEBUG("Session Missed: Polling with blank requests: ~p", [Response]),
      timer:sleep(100),
      handle_session(Sid, Rid + 1, [], [], 0, StreamStart, IP, Count + 1);
    _ ->
      ?DEBUG("Session Failed", []),
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
      handle_http_put(Sid, Rid, Attrs, Payload, PayloadSize, StreamStart, IP);
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
