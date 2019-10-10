%% @author Jeremy Ong
%% @author Michael Coles
%% @doc Erlang websocket client (FSM implementation)
-module(websocket_client).

-behaviour(gen_fsm).
%-compile([export_all]).

-include("websocket_req.hrl").

-export([start_link/3]).
-export([start_link/4]).
-export([start_link/5]).
-export([cast/2]).
-export([send/2]).

-export([init/1]).
-export([terminate/3]).
-export([handle_event/3]).
-export([handle_sync_event/4]).
-export([handle_info/3]).
-export([code_change/4]).

% States
-export([disconnected/2]).
-export([disconnected/3]).
-export([connected/2]).
-export([connected/3]).
-export([handshaking/2]).
-export([handshaking/3]).
-export([proxy_handshaking/2]).
-export([proxy_handshaking/3]).

-type state_name() :: atom().

-type state() :: any().
-type keepalive() :: non_neg_integer().
-type close_type() :: normal | error | remote.
-type reason() :: term().

% Create handler state based on options.
-callback init(list()) ->
    {ok, state()} % Will start `disconnected`.
    | {once, state()} % Will attempt to connect once only.
    | {reconnect, state()}. % Will keep trying to connect.

% Called when a websocket connection is established, including
% successful handshake with the other end.
-callback onconnect(websocket_req:req(), state()) ->
    % Simple client: only server-initiated pings will be
    % automatically responded to.
    {ok, state()}
    % Keepalive client: will automatically initiate a ping to the server
    % every keepalive() ms.
    | {ok, state(), keepalive()}
    % Immediately send a message to the server.
    | {reply, websocket_req:frame(), state()}
    % Close the connection.
    | {close, binary(), state()}.

% Called when the socket is closed for any reason.
-callback ondisconnect(reason(), state()) ->
    % Return to `disconnected` state but keep process alive.
    {ok, state()}
    % Immediately attempt to reconnect.
    | {reconnect, state()}
    % Reconnect after interval.
    | {reconnect, non_neg_integer(), state()}
    % Shut the process down cleanly.
    | {close, reason(), state()}.

% Called for every received frame from the server.
% NB this will also get called for pings, which are automatically ponged.
-callback websocket_handle({text | binary | ping | pong, binary()}, websocket_req:req(), state()) ->
    % Do nothing.
    {ok, state()}
    % Send the given frame to the server.
    | {reply, websocket_req:frame(), state()}
    % Shut the process down cleanly.
    | {close, binary(), state()}.

% Called for any received erlang message.
-callback websocket_info(any(), websocket_req:req(), state()) ->
    % Do nothing.
    {ok, state()}
    % Send the given frame to the server.
    | {reply, websocket_req:frame(), state()}
    % Shut the process down cleanly.
    | {close, binary(),  state()}.

% Called when the process exits abnormally.
-callback websocket_terminate({close_type(), term()} | {close_type(), integer(), binary()},
                              websocket_req:req(), state()) ->
    ok.

-record(context,
        {
         wsreq     :: websocket_req:req(),
         transport :: #transport{},
         headers   :: list({string(), string()}),
         target    :: {Proto :: ws | wss,
                      Host :: string(), Port :: non_neg_integer(),
                      Path :: string()},
         handler   :: {module(), HState :: term()},
         buffer = <<>> :: binary(),
         reconnect :: boolean(),
         reconnect_tref = undefined :: undefined | reference(),
         ka_attempts = 0 :: non_neg_integer(),
         proxy = undefined
        }).

%% @doc Start the websocket client
%%
%% URL : Supported schema: (ws | wss)
%% Handler: module()
%% Args : arguments to pass to Handler:init/1
-spec start_link(URL :: string(), Handler :: module(), Args :: list()) ->
    {ok, pid()} | {error, term()}.
start_link(URL, Handler, Args) ->
    start_link(URL, Handler, Args, []).

%% @doc Start the websocket client
%%
%% Supported Opts:
%%  - {keepalive, integer()}:  keepalive timeout in ms
%%  - {extra_headers, list({K, V})}: a kv-list of headers to send in the handshake
%% (useful if you need to add an e.g. 'Origin' header on connection.
%%  - {ssl_verify, verify_none | verify_peer | {verify_fun, _}} : this is passed
%%  through to ssl:connect/2,3.
start_link(URL, Handler, HandlerArgs, Opts) ->
    start_link(undefined, URL, Handler, HandlerArgs, Opts).

%% @doc Start the websocket client
%% see gen_fsm:start_link(FsmName, Module, Args, Options)
%% FsmName = {local,Name} | {global,GlobalName} | {via,Module,ViaName}
%%  Name = atom()
%%  GlobalName = ViaName = term()
%%  Module = atom()
start_link(FsmName, URL, Handler, HandlerArgs, Opts) when is_binary(URL) ->
  start_link(FsmName, binary_to_list(URL), Handler, HandlerArgs, Opts);
start_link(FsmName, URL, Handler, HandlerArgs, Opts) when is_list(Opts) ->
    case http_uri:parse(URL, [{scheme_defaults, [{ws,80},{wss,443}]}]) of
        {ok, {Protocol, _, Host, Port, Path, Query}} ->
            InitArgs = [Protocol, Host, Port, Path ++ Query, Handler, HandlerArgs, Opts],
            %FsmOpts = [{dbg, [trace]}],
            FsmOpts = [],
            fsm_start_link(FsmName, InitArgs, FsmOpts);
        {error, _} = Error ->
            Error
    end.

fsm_start_link(undefined, Args, Options) ->
    gen_fsm:start_link(?MODULE, Args, Options);
fsm_start_link(FsmName, Args, Options) ->
    gen_fsm:start_link(FsmName, ?MODULE, Args, Options).

send(Client, Frame) ->
    gen_fsm:sync_send_event(Client, {send, Frame}).

%% Send a frame asynchronously
-spec cast(Client :: pid(), websocket_req:frame()) -> ok.
cast(Client, Frame) ->
    gen_fsm:send_event(Client, {cast, Frame}).

-spec init(list(any())) ->
    {ok, state_name(), #context{}}.
    %% NB DO NOT try to use Timeout to do keepalive.
init([Protocol, Host, Port, Path, Handler, HandlerArgs, Opts]) ->
    {Connect, Reconnect, HState} =
        case Handler:init(HandlerArgs) of
            {ok, State} -> {false, false, State};
            {once, State} -> {true, false, State};
            {reconnect, State} -> {true, true, State}
        end,
    SSLVerify = proplists:get_value(ssl_verify, Opts, verify_none),
    SockOpts  = proplists:get_value(socket_opts, Opts, []),
    Transport = transport(Protocol, ssl_verify(SSLVerify), SockOpts),
    WSReq = websocket_req:new(
                Protocol, Host, Port, Path,
                Transport, wsc_lib:generate_ws_key()
            ),
    WSReq1 = case proplists:get_value(keepalive, Opts) of
        undefined -> WSReq;
        KeepAlive ->
            % NB: there's no need to start the actual KA mechanism until we're
            % actually connected.
            websocket_req:keepalive(KeepAlive, WSReq)
    end,
    Context0 = #context{
                  transport = Transport,
                  headers   = proplists:get_value(extra_headers, Opts, []),
                  wsreq     = WSReq1,
                  target    = {Protocol, Host, Port, Path},
                  handler   = {Handler, HState},
                  reconnect = Reconnect
                 },
    Context1 =  set_proxy(Context0, Opts),

    Connect andalso gen_fsm:send_event(self(), connect),
    {ok, disconnected, Context1}.

set_proxy(Context, Opts) ->
    Host = proplists:get_value(proxy_host, Opts),
    Port = proplists:get_value(proxy_port, Opts),
    Context#context{proxy = {Host, Port}}.

-spec transport(ws | wss, {verify | verify_fun, term()},
                list(inet:option())) -> #transport{}.
transport(wss, SSLVerify, ExtraOpts) ->
    #transport{
       mod = ssl,
       name = ssl,
       closed = ssl_closed,
       error = ssl_error,
       opts = [
               {mode, binary},
               {active, true},
               SSLVerify,
               {packet, 0}
               | ExtraOpts
              ]};
transport(ws, _, ExtraOpts) ->
    #transport{
        mod = gen_tcp,
        name = tcp,
        closed = tcp_closed,
        error = tcp_error,
        opts = [
                {mode, binary},
                {active, true},
                {packet, 0}
                | ExtraOpts
               ]}.

ssl_verify(verify_none) ->
    {verify, verify_none};
ssl_verify(verify_peer) ->
    {verify, verify_peer};
ssl_verify({verify_fun, _}=Verify) ->
    Verify.

-spec terminate(Reason :: term(), state_name(), #context{}) -> ok.
%% TODO Use Reason!!
terminate(Reason, StateName,
          #context{
             transport=T,
             wsreq=WSReq
            }) ->
    case websocket_req:socket(WSReq) of
        undefined -> ok;
        Socket ->
            _ = (T#transport.mod):close(Socket)
    end,
    ok.

connect(#context{
           transport = _T,
           wsreq = WSReq0,
           headers = Headers,
           target = {_Protocol, Host, Port, _Path},
           ka_attempts = KAs
          } = Context) ->
    Context2 = maybe_cancel_reconnect(Context),
    case open_connection(Context2) of
        {ok, Socket} ->
            ok = Socket,
            WSReq1 = websocket_req:socket(Socket, WSReq0),
            maybe_send_proxy_handshake(WSReq1, Headers, Context2); 
            % case websocket_req:keepalive(WSReq1) of
            %     infinity ->
            %         {next_state, proxy_handshaking, Context2#context{ wsreq=WSReq1}};
            %     KeepAlive ->
            %         NewTimer = erlang:send_after(KeepAlive, self(), keepalive),
            %         WSReq2 = websocket_req:set([{keepalive_timer, NewTimer}], WSReq1),
            %         {next_state, handshaking, Context2#context{wsreq=WSReq2, ka_attempts=(KAs+1)}}
            % end;
        {error, _} = Error ->
            disconnect(Error, Context2)
    end.

open_connection(#context{
                    proxy = undefined,
                    transport = T,
                    target = {_Protocol, Host, Port, _Path}
                }) ->
    (T#transport.mod):connect(Host, Port, T#transport.opts);
open_connection(#context{
                    proxy = {Host, Port}
                }) ->
    Opts = [{mode, binary},{active, true},{packet, 0}],
    gen_tcp:connect(Host, Port, Opts).

maybe_send_proxy_handshake(WSReq, Headers, #context{proxy = undefined} = Context) ->
    ok = WSReq,
    case send_handshake(WSReq, Headers, Context) of
        ok ->
            {next_state, handshaking,  Context#context{wsreq = WSReq}};
        Error ->
            disconnect(Error, Context)
    end;
maybe_send_proxy_handshake(WSReq, Headers, #context{proxy = {_Host, _Port}} = Context) ->
    case send_proxy_handshake(WSReq, Headers, Context) of
        ok ->
            {next_state, proxy_handshaking,  Context#context{wsreq = WSReq}};
        Error ->
            disconnect(Error, Context)
    end.

disconnect(Reason, #context{
                      wsreq=WSReq0,
                      handler={Handler, HState0}
                     }=Context) ->
    case Handler:ondisconnect(Reason, HState0) of
        {ok, HState1} ->
            {next_state, disconnected, Context#context{buffer = <<>>, handler={Handler, HState1}}};
        {reconnect, HState1} ->
            ok = gen_fsm:send_event(self(), connect),
            {next_state, disconnected, Context#context{handler={Handler, HState1}}};
        {reconnect, Interval, HState1} ->
            Tref = gen_fsm:send_event_after(Interval, connect),
            {next_state, disconnected, Context#context{handler={Handler, HState1}, reconnect_tref=Tref}};
        {close, Reason1, HState1} ->
            ok = websocket_close(WSReq0, Handler, HState1, Reason1),
            {stop, Reason1, Context#context{handler={Handler, HState1}}}
    end.

disconnected(connect, Context0) ->
    connect(Context0);
disconnected(_Event, Context) ->
    % ignore
    {next_state, disconnected, Context}.

disconnected(connect, _From, Context0) ->
    %% TODO FIXME This really seems wrong and too easy
    case connect(Context0) of
        {next_state, State, Context1} ->
            {reply, ok, State, Context1};
        Other ->
            Other
    end;
disconnected(_Event, _From, Context) ->
    {reply, {error, unhandled_sync_event}, disconnected, Context}.

connected(connect, Context) ->
    %% We didn't cancel the reconnect_tref timer before the event was
    %% sent
    {next_state, connected, Context};
connected({cast, Frame}, #context{wsreq=WSReq}=Context) ->
    case encode_and_send(Frame, WSReq) of
        ok ->
            {next_state, connected, Context};
        {error, closed} ->
            {next_state, disconnected, Context}
    end.

connected({send, Frame}, _From, #context{wsreq=WSReq}=Context) ->
    {reply, encode_and_send(Frame, WSReq), connected, Context};
connected(_Event, _From, Context) ->
    {reply, {error, unhandled_sync_event}, connected, Context}.

proxy_handshaking(_Event, Context) ->
    {next_state, proxy_handshaking, Context}.
proxy_handshaking(_Event, _From, Context) ->
    {reply, {error, unhandled_sync_event}, proxy_handshaking, Context}.

handshaking(_Event, Context) ->
    {next_state, handshaking, Context}.
handshaking(_Event, _From, Context) ->
    {reply, {error, unhandled_sync_event}, handshaking, Context}.

-spec handle_event(Event :: term(), state_name(), #context{}) ->
    {next_state, state_name(), #context{}}
    | {stop, Reason :: term(), #context{}}.
handle_event(_Event, State, Context) ->
    {next_state, State, Context}. %% i.e. ignore, do nothing

-spec handle_sync_event(Event :: term(), {From :: pid(), any()}, state_name(), #context{}) ->
    {next_state, state_name(), #context{}}
    | {reply, Reply :: term(), state_name(), #context{}}
    | {stop, Reason :: term(), #context{}}
    | {stop, Reason :: term(), Reply :: term(), #context{}}.
handle_sync_event(Event, {_From, Tag}, State, Context) ->
    {reply, {noop, Event, Tag}, State, Context}.

-spec handle_info(Info :: term(), state_name(), #context{}) ->
    {next_state, state_name(), #context{}}
    | {stop, Reason :: term(), #context{}}.
% handle_info(keepalive, KAState, #context{ wsreq=WSReq, ka_attempts=KAAttempts }=Context)
%   when KAState =:= handshaking; KAState =:= connected ->
%     [KeepAlive, KATimer, KAMax] =
%         websocket_req:get([keepalive, keepalive_timer, keepalive_max_attempts], WSReq),
%     case KATimer of
%         undefined -> ok;
%         _ -> erlang:cancel_timer(KATimer)
%     end,
%     case KAAttempts of
%         KAMax->
%             disconnect({error, keepalive_timeout}, Context);
%         _ ->
%             ok = encode_and_send({ping, <<"foo">>}, WSReq),
%             NewTimer = erlang:send_after(KeepAlive, self(), keepalive),
%             WSReq1 = websocket_req:set([{keepalive_timer, NewTimer}], WSReq),
%             {next_state, KAState, Context#context{wsreq=WSReq1, ka_attempts=(KAAttempts+1)}}
%     end;
%% TODO Move Socket into #transport{} from #websocket_req{} so that we can
%% match on it here
handle_info({TransClosed, _Socket}, _CurrState,
            #context{
               transport=#transport{ closed=TransClosed } %% NB: matched
              }=Context) ->
    disconnect({remote, closed}, Context);
handle_info({TransError, _Socket, Reason},
            _AnyState,
            #context{
               transport=#transport{ error=TransError},
               handler={Handler, HState0},
               wsreq=WSReq
              }=Context) ->
    ok = websocket_close(WSReq, Handler, HState0, {TransError, Reason}),
    {stop, {socket_error, Reason}, Context};
handle_info({Trans, _Socket, Data},
            proxy_handshaking,
            #context{
               transport = #transport{name = Trans},
               wsreq = WSReq0,
               headers = Headers,
               handler = {Handler, HState0},
               buffer = Buffer
            } = Context0) ->
    MaybeHandshakeResp = << Buffer/binary, Data/binary >>,
    case wsc_lib:validate_proxy_handshake(MaybeHandshakeResp, websocket_req:key(WSReq0)) of
        {error, _} = Error ->
            ok = {Error, MaybeHandshakeResp},
            disconnect(Error, Context0);
        {notfound, _} ->
            {next_state, proxy_handshaking, Context0#context{buffer = MaybeHandshakeResp}};
        {ok, Remaining} ->
            case send_handshake(WSReq0, Headers, Context0) of
                ok ->
                    handle_websocket_frame(Remaining, Context0#context{buffer = <<>>}, handshaking);
                {error, Error} ->
                  {stop, error, Context0}
            end
    end;
handle_info({Trans, _Socket, Data},
            handshaking,
            #context{
               transport = #transport{ name=Trans },
               wsreq = WSReq0,
               handler = {Handler, HState0},
               buffer = Buffer
              } = Context0) ->
    MaybeHandshakeResp = << Buffer/binary, Data/binary >>,
    case wsc_lib:validate_handshake(MaybeHandshakeResp, websocket_req:key(WSReq0)) of
        {error,_} = Error ->
            ok = {Error, MaybeHandshakeResp},
            disconnect(Error, Context0);
        {notfound, _} ->
            {next_state, handshaking, Context0#context{buffer = MaybeHandshakeResp}};
        {ok, Remaining} ->
            case maybe_upgrade_socket(Context0) of
                {ok, #context{wsreq = WSReq1} = Context1} ->
                    {ok, HState2, KeepAlive} =
                        case Handler:onconnect(WSReq1, HState0) of
                            {ok, HState1} ->
                                KA = websocket_req:keepalive(WSReq1),
                                {ok, HState1, KA};
                            {ok, _HS1, KA}=Result ->
                                % erlang:send_after(KA, self(), keepalive),
                                Result
                        end,
                    WSReq2 = websocket_req:keepalive(KeepAlive, WSReq1),
                    handle_websocket_frame(
                      Remaining,
                      Context1#context{
                                wsreq = WSReq2,
                                handler = {Handler, HState2},
                                buffer = <<>>
                      },
                      connected
                    );
                {error, Error} ->
                  ok = Error,
                  {stop, error, Context0}
            end
    end;
handle_info({Trans, _Socket, Data},
            connected,
            #context{
               transport=#transport{ name=Trans }
              }=Context) ->
    handle_websocket_frame(Data, Context, connected);
handle_info(Msg, State,
            #context{
               wsreq=WSReq,
               handler={Handler, HState0},
               buffer=Buffer
              }=Context) ->
    try Handler:websocket_info(Msg, WSReq, HState0) of
        HandlerResponse ->
            case handle_response(HandlerResponse, Handler, WSReq) of
                {ok, WSReqN, HStateN} ->
                    {next_state, State, Context#context{
                                          handler={Handler, HStateN},
                                          wsreq=WSReqN,
                                          buffer=Buffer}};
                {close, Reason, WSReqN, Handler, HStateN} ->
                    {stop, Reason, Context#context{
                                     wsreq=WSReqN,
                                     handler={Handler, HStateN}}}
            end
    catch Class:Reason:Stacktrace ->
        %% TODO Maybe a function_clause catch here to allow
        %% not having to have a catch-all clause in websocket_info CB?
        error_logger:error_msg(
          "** Websocket client ~p terminating in ~p/~p~n"
          "   for the reason ~p:~p~n"
          "** Last message was ~p~n"
          "** Handler state was ~p~n"
          "** Stacktrace: ~p~n~n",
          [Handler, websocket_info, 3, Class, Reason, Msg, HState0, Stacktrace]),
        websocket_close(WSReq, Handler, HState0, Reason),
        {stop, Reason, Context}
    end.

maybe_upgrade_socket(#context{proxy = undefined} = Context) ->
    {ok, Context};
maybe_upgrade_socket(#context{transport = T, wsreq = Req0} = Context) ->
    case T#transport.name of
        ssl ->
            Socket = websocket_req:socket(Req0),
            case ssl:connect(Socket, T#transport.opts) of
                {ok, SSLSocket} ->
                  Req1 = websocket_req:socket(SSLSocket, Req0),
                  {ok, Context#context{wsreq = Req1}};
                {error, Error} ->
                    gen_tcp:close(Socket),
                    {error, Error}
            end;    
        tcp ->
            {ok, Context}
    end.

% Recursively handle all frames that are in the buffer;
% If the last frame is incomplete, leave it in the buffer and wait for more.
handle_websocket_frame(Data, #context{}=Context0, NextState) ->
    Context = Context0#context{ka_attempts=0},
    #context{
               handler={Handler, HState0},
               wsreq=WSReq,
               buffer=Buffer} = Context,
    Result =
        case websocket_req:remaining(WSReq) of
            undefined ->
                wsc_lib:decode_frame(WSReq, << Buffer/binary, Data/binary >>); %% TODO ??
            Remaining ->
                wsc_lib:decode_frame(WSReq, websocket_req:opcode(WSReq), Remaining, Data, Buffer)
        end,
    case Result of
        {frame, Message, WSReqN, BufferN} ->
            case Message of
                {ping, Payload} -> ok = encode_and_send({pong, Payload}, WSReqN);
                _ -> ok
            end,
            try
                HandlerResponse = Handler:websocket_handle(Message, WSReqN, HState0),
                WSReqN2 = websocket_req:remaining(undefined, WSReqN),
                case handle_response(HandlerResponse, Handler, WSReqN2) of
                    {ok, WSReqN2, HStateN2} ->
                        Context2 = Context#context{
                                     handler = {Handler, HStateN2},
                                     wsreq = WSReqN2,
                                     buffer = <<>>},
                        case BufferN of
                            <<>> ->
                                {next_state, NextState, Context2};
                            _ ->
                                handle_websocket_frame(BufferN, Context2, NextState)
                        end;
                    {close, Error, WSReqN2, Handler, HStateN2} ->
                        {stop, Error, Context#context{
                                         wsreq=WSReqN2,
                                         handler={Handler, HStateN2}}}
                end
            catch Class:Reason:Stacktrace ->
              error_logger:error_msg(
                "** Websocket client ~p terminating in ~p/~p~n"
                "   for the reason ~p:~p~n"
                "** Websocket message was ~p~n"
                "** Handler state was ~p~n"
                "** Stacktrace: ~p~n~n",
                [Handler, websocket_handle, 3, Class, Reason, Message, HState0, Stacktrace]),
              {stop, Reason, Context#context{ wsreq=WSReqN }}
            end;
        {recv, WSReqN, BufferN} ->
            {next_state, NextState, Context#context{
                                      handler={Handler, HState0},
                                      wsreq=WSReqN,
                                      buffer=BufferN}};
        {close, _Reason, WSReqN} ->
            {next_state, disconnected, Context#context{wsreq=WSReqN,
                                                       buffer= <<>>}}
    end.


-spec code_change(OldVsn :: term(), state_name(), #context{}, Extra :: any()) ->
    {ok, state_name(), #context{}}.
code_change(_OldVsn, StateName, Context, _Extra) ->
    {ok, StateName, Context}.

%% @doc Handles return values from the callback module
handle_response({ok, HandlerState}, _Handler, WSReq) ->
    {ok, WSReq, HandlerState};
handle_response({reply, Frame, HandlerState}, Handler, WSReq) ->
    case encode_and_send(Frame, WSReq) of
        ok -> {ok, WSReq, HandlerState};
        Reason -> {close, Reason, WSReq, Handler, HandlerState}
    end;
handle_response({close, Payload, HandlerState}, Handler, WSReq) ->
    encode_and_send({close, Payload}, WSReq),
    {close, normal, WSReq, Handler, HandlerState}.

%% @doc Send http upgrade request and validate handshake response challenge
-spec send_handshake(WSReq :: websocket_req:req(), [{string(), string()}], #context{}) -> ok.
send_handshake(WSReq, ExtraHeaders, Context) ->
    Handshake = wsc_lib:create_handshake(WSReq, ExtraHeaders),
    send_handshake(Handshake, WSReq, ExtraHeaders, Context).

-spec send_proxy_handshake(WSReq :: websocket_req:req(), [{string(), string()}], #context{}) -> ok.
send_proxy_handshake(WSReq, ExtraHeaders, Context) ->
    Handshake = wsc_lib:create_proxy_handshake(WSReq, ExtraHeaders),
    send_handshake(Handshake, WSReq, ExtraHeaders, Context).

%% @doc Send http upgrade request and validate handshake response challenge
-spec send_handshake(Handshake :: iolist(), WSReq :: websocket_req:req(), [{string(), string()}], #context{}) ->
    ok
    | {error, term()}.
send_handshake(Handshake, WSReq, ExtraHeaders, #context{proxy = Proxy} = Context) ->
    [Transport, Socket] = websocket_req:get([transport, socket], WSReq),
    case Proxy of
      undefined ->
          transport = Transport#transport.mod,
          (Transport#transport.mod):send(Socket, Handshake);
      {_Host, _Port} ->
          gen_tcp:send(Socket, Handshake)
    end.

%% @doc Send frame to server
encode_and_send(Frame, WSReq) ->
    case websocket_req:get([socket, transport], WSReq) of
        [undefined, _Transport] ->
            {error, disconnected};
        [Socket, Transport] ->
            (Transport#transport.mod):send(Socket, wsc_lib:encode_frame(Frame))
    end.

-spec websocket_close(WSReq :: websocket_req:req(),
                      Handler :: module(),
                      HandlerState :: any(),
                      Reason :: tuple()) -> ok.
websocket_close(WSReq, Handler, HandlerState, Reason) ->
    try
        Handler:websocket_terminate(Reason, WSReq, HandlerState)
    catch Class:Reason2 ->
      error_logger:error_msg(
        "** Websocket handler ~p terminating in ~p/~p~n"
        "   for the reason ~p:~p~n"
        "** Handler state was ~p~n"
        "** Stacktrace: ~p~n~n",
        [Handler, websocket_terminate, 3, Class, Reason2, HandlerState,
          erlang:get_stacktrace()])
    end.
%% TODO {stop, Reason, Context}

maybe_cancel_reconnect(Context=#context{reconnect_tref = undefined}) ->
    Context;
maybe_cancel_reconnect(Context=#context{reconnect_tref=Tref}) when is_reference(Tref) ->
    gen_fsm:cancel_timer(Tref),
    Context#context{reconnect_tref=undefined}.

