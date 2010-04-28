%%%----------------------------------------------------------------------
%%% File    : ejabberd_http_pre_bind.erl
%%% Author  : Nathan Zorn <nathan@collecta.com>
%%% Purpose : Implements Pre-Bind XMPP over BOSH (XEP-0205) 
%%%----------------------------------------------------------------------

-module(ejabberd_http_pre_bind).



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
	    handle_auth(Sid, Rid+1, Attrs, Payload, 
			PayloadSize, StreamStart, IP, Count+1);
	_ ->
	    Rid
    end.
handle_bind(_, Rid, _, ?MAX_COUNT) ->
    {Rid, {200,
	   [{"Content-Type","text/xml; charset=utf-8"}],
	   []}};
handle_bind(Sid, Rid, IP, Count) ->
    BindAttrs = [{"rid",integer_to_list(Rid)},
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
	    handle_bind(Sid, Rid+1, IP, Count+1)
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
    RidA = handle_auth(Sid, 
		       Rid+1, 
		       AuthAttrs, 
		       AuthPayload, 
		       AuthPayloadSize, 
		       false, 
		       IP,
		       0),
    StreamAttrs = [{"rid",integer_to_list(RidA+1)},
		   {"sid",Sid},
		   {"xmlns",?NS_HTTP_BIND},
		   {"xml:lang","en"},
		   {"xmlns:xmpp","urn:xmpp:xbosh"},
		   {"to",XmppDomain},
		   {"xmpp:restart","true"}],
    handle_http_put(Sid,
                    RidA+1,
                    StreamAttrs,
                    [],
                    191,
                    true,
                    IP),
    {RidB, Retval} = handle_bind(Sid, RidA+2, IP, 0),
    
    SessionAttrs = [{"rid",integer_to_list(RidB+1)},
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
                    RidB+1,
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

