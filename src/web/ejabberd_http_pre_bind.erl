%%%----------------------------------------------------------------------
%%% File    : ejabberd_http_pre_bind.erl
%%% Author  : Nathan Zorn <nathan@collecta.com>
%%% Purpose : Implements Pre-Bind XMPP over BOSH (XEP-0205) 
%%%----------------------------------------------------------------------

-module(ejabberd_http_pre_bind).

-behaviour(gen_fsm).

%% External exports
-export([code_change/4,
	 process_request/2]).

-include("ejabberd.hrl").
-include("jlib.hrl").
-include("ejabberd_http.hrl").

-define(NS_HTTP_BIND, "http://jabber.org/protocol/httpbind").
-define(HEADER, [{"Content-Type", "text/xml; charset=utf-8"}, 
                 {"Access-Control-Allow-Origin", "*"}, 
                 {"Access-Control-Allow-Headers", "Content-Type"}]).

%% handle http put similar to bind, but withouth send_outpacket
handle_http_put(Sid, Rid, Attrs, Payload, PayloadSize, StreamStart, IP) ->
    case ejabberd_http_bind:http_put(Sid, Rid, Attrs, Payload, PayloadSize, StreamStart, IP) of
        {error, not_exists} ->
            ?DEBUG("no session associated with sid: ~p", [Sid]),
            {404, ?HEADER, ""};
        {{error, Reason}, _Sess} ->
            ?DEBUG("Error on HTTP put. Reason: ~p", [Reason]),
            %% ignore errors
            {200, ?HEADER, "<body xmlns='"++?NS_HTTP_BIND++"'/>"}; 
        {{repeat, OutPacket}, Sess} ->
            ?DEBUG("http_put said 'repeat!' ...~nOutPacket: ~p", [OutPacket]),
            send_outpacket(Sess, OutPacket);            
        {{wait, Pause}, _Sess} ->
	    ?DEBUG("Trafic Shaper: Delaying request ~p", [Rid]),
	    timer:sleep(Pause),
            handle_http_put(Sid, Rid, Attrs, Payload, PayloadSize,
			    StreamStart, IP);
        {buffered, _Sess} ->
            ?DEBUG("buffered", []),
            {200, ?HEADER, "<body xmlns='"++?NS_HTTP_BIND++"'/>"};
        {ok, Sess} ->
            ejabberd_http_bind:prepare_response(Sess, Rid, Attrs, StreamStart)
    end.

%% Entry point for data coming from client through ejabberd HTTP server:
process_request(Data, IP) ->
    {ok,{Rid,XmppDomain,Attrs}} = parse_request(Data),
    Sid = sha:sha(term_to_binary({now(), make_ref()})),
    {ok, Pid} = ejabberd_http_bind:start(XmppDomain, Sid, "", IP),
    StartAttrs = [{"rid",Rid},
		  {"to",XmppDomain},
		  {"xmlns",?NS_HTTP_BIND},
		  {"xml:lang","en"},
		  {"xmpp:version","1.0"},
		  {"ver","1.6"},
		  {"xmlns:xmpp","urn:xmpp:bosh"},
		  {"window","5"},
		  {"content","text/xml"},
		  {"charset","utf-8"}],
    StartAttrs0 = lists:append(StartAttrs,Attrs),
    Payload = [],
    PayloadSize = 0,
    ejabberd_http_bind:handle_session_start(Pid,
					    XmppDomain,
					    Sid,
					    Rid,
					    StartAttrs0,
					    Payload,
					    PayloadSize,
					    IP),
    %After session start, send the anonymous authentication mechanism.
    AuthAttrs = [{"rid",integer_to_list(Rid+1)},
		 {"xmlns",?NS_HTTP_BIND},
		 {"sid",Sid}],
    AuthPayload = [{xmlelement,
		   "auth",
		   [{"xmlns","urn:ietf:params:xml:ns:xmpp-sasl"},
		    {"mechanism","ANONYMOUS"}],
		   []}],
    AuthPayloadSize = 191,
    handle_http_put(Sid, 
                    Rid+1, 
                    AuthAttrs, 
                    AuthPayload, 
                    AuthPayloadSize, 
                    false, 
                    IP),
    StreamAttrs = [{"rid",integer_to_list(Rid+2)},
		   {"sid",Sid},
		   {"xmlns",?NS_HTTP_BIND},
		   {"xml:lang","en"},
		   {"xmlns:xmpp","urn:xmpp:xbosh"},
		   {"to",XmppDomain},
		   {"xmpp:restart","true"}],
    handle_http_put(Sid,
                    Rid+2,
                    StreamAttrs,
                    [],
                    191,
                    true,
                    IP),
    BindAttrs = [{"rid",integer_to_list(Rid+3)},
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
    {_,_,Retval0} = handle_http_put(Sid,
                                    Rid+3,
                                    BindAttrs,
                                    BindPayload,
                                    BindPayloadSize,
                                    false,
                                    IP),
    {xmlelement,"body",RetAttrs,Els} = xml_stream:parse_element(Retval0),
    XmlElementString = xml:element_to_string({xmlelement,"body",
					      RetAttrs ++ [{"sid",Sid}] ++ [{"rid",integer_to_list(Rid+4)}],
					      Els}),
    Retval = {200,
	      [{"Content-Type","text/xml; charset=utf-8"}],
	      XmlElementString},
    SessionAttrs = [{"rid",integer_to_list(Rid+4)},
		    {"xmlns",?NS_HTTP_BIND},
		    {"sid",Sid}],
    SessionPayload = [{xmlelement,"iq",
		       [{"type","set"},
			{"id","_session_auth_2"},
			{"xmlns","jabber:client"}],
		       [{xmlelement,"session",
			 [{"xmlns",
			   "urn:ietf:params:xml:ns:xmpp-session"}],[]}]}],
    SessionPayloadSize = 228,
    handle_http_put(Sid, 
                    Rid+4,
                    SessionAttrs,
                    SessionPayload,
                    SessionPayloadSize,
                    false,
                    IP),
    Retval.

code_change(_OldVsn, StateName, StateData, _Extra) ->
    {ok, StateName, StateData}.
%% Parse the initial client request to start the pre bind session.
%% TODO: add real user support
parse_request(Data) ->
    case xml_stream:parse_element(Data) of
        {xmlelement, "body", Attrs, _Els} ->
	    case catch list_to_integer(xml:get_attr_s("rid", Attrs)) of
		{'EXIT', _} ->
		    ?ERROR_MSG("error in body ~p",["Exit"]),
		    {error, bad_request};
		Rid ->
		    XmppDomain = xml:get_attr_s("to",Attrs),
		    RetAttrs = [{"wait",xml:get_attr_s("wait",Attrs)},
				{"hold",xml:get_attr_s("hold",Attrs)}],
		    {ok, {Rid, XmppDomain,RetAttrs}}
	    end;
	{xmlelement, _Name, _Attrs, _Els} ->
	    ?ERROR_MSG("Not a body ~p",[_Name]),
            {error, bad_request};
        {error, _Reason} ->
	    ?ERROR_MSG("Error with parse. ~p",[_Reason]),
            {error, bad_request}
    end.
