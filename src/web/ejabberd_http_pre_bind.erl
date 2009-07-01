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
    {_,A} = ejabberd_http_bind:http_put(Sid,
				Rid+1,
				AuthAttrs,
				AuthPayload,
				AuthPayloadSize,
					   false,
				IP),
    ejabberd_http_bind:prepare_response(A,
					Rid+1,
					AuthAttrs,
					false),
    
    StreamAttrs = [{"rid",integer_to_list(Rid+2)},
		   {"sid",Sid},
		   {"xmlns",?NS_HTTP_BIND},
		   {"xml:lang","en"},
		   {"xmlns:xmpp","urn:xmpp:xbosh"},
		   {"to",XmppDomain},
		   {"xmpp:restart","true"}],
    {_,B} = ejabberd_http_bind:http_put(Sid,
					Rid+2,
					StreamAttrs,
					[],
					191,
					true,
					IP),
    ejabberd_http_bind:prepare_response(B,
					Rid+2,
					StreamAttrs,
					true),
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
    {_,Put} = ejabberd_http_bind:http_put(Sid,
					  Rid+3,
					  BindAttrs,
					  BindPayload,
					  BindPayloadSize,
					  false,
					  IP
					 ),    
    {_,_,Retval0} = ejabberd_http_bind:prepare_response(Put,
						  Rid+3,
						  BindAttrs,
						  false),
    {xmlelement,"body",RetAttrs,Els} = xml_stream:parse_element(Retval0),
    XmlElementString = xml:element_to_string({xmlelement,"body",
					      RetAttrs ++ [{"sid",Sid}] ++ [{"rid",integer_to_list(Rid+3)}],
					      Els}),
    Retval = {200,
	      [{"Content-Type","text/xml; charset=utf-8"}],
	      XmlElementString},
    Retval.

code_change(_OldVsn, StateName, StateData, _Extra) ->
    {ok, StateName, StateData}.
%%Parse the initial client request to start the pre bind session.
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
