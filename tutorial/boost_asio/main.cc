#include <chrono>
#include <iostream>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>

#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include <rtm.h>

// Replace these values with your project's credentials
// from DevPortal (https://developer.satori.com/)
static char const *endpoint = YOUR_ENDPOINT;
static char const *appkey = YOUR_APPKEY;
// Role and secret are optional: replace only if you need to authenticate.
static char const *role = YOUR_ROLE;
static char const *role_secret = YOUR_ROLE_SECRET;

/**
 * Rtm class encapsulates the C API. It is a thin wrapper, incorporating
 * boost::asio.
 */
class Rtm {
	public:
		/**
		 * Functor type for status callbacks
		 *
		 * We will use it below to allow the user to react to the successful
		 * completion of authentication and subscription. Passed a success
		 * state and an optional error message.
		 */
		using callback_type = std::function<void(bool, const char *)>;

		/**
		 * Functor type for messages
		 *
		 * Used below for incoming messages on channels we subscribed to.
		 */
		using message_handler_type = std::function<void(const char *)>;

		/**
		 * Default constructor for Rtm
		 *
		 * \param io_service The boost::io_service you want to use for this
		 *                   connection
		 */
		Rtm(boost::asio::io_service &io_service) :
				m_sd(io_service),
				m_ping_timer(io_service),
				m_online(false) {
			// Allocate memory for RTM and initialize it
			m_rtm_memory.resize(rtm_client_size);
			m_rtm_ptr = rtm_init(&m_rtm_memory[0],
					[](rtm_client_t *rtm, const rtm_pdu_t *pdu) {
						Rtm *this_ptr = static_cast<Rtm *>(rtm_get_user_context(rtm));
						this_ptr->handle_pdu(pdu);
					},
					this);
		}

		/**
		 * Establish a connection to Satori.
		 *
		 * \param endpoint The endpoint assigned to you
		 * \param appkey   The appkey assigned to you
		 * \param role     The role. Optional, you may pass a nullptr to skip
		 *                 authentication.
		 * \param secret   The secret associated with the role. Only used if a
		 *                 role is supplied as well.
		 * \param connected_callback User callback invoked once a connection
		 *                 has been established and authentication was
		 *                 successful, or upon error.
		 */
		void connect(const char *endpoint, const char *appkey,
				const char *role, const char *secret,
				const callback_type &connected_callback) {
			// Establish a connection to Satori
			if(rtm_connect(m_rtm_ptr, endpoint, appkey) != RTM_OK) {
				if(connected_callback)
					connected_callback(false, "Connecting to endpoint with appkey failed.");
				return;
			}

			// Since we are now connected, we will have to send "ping"s in
			// regular intervals if we are not doing anything else, to keep
			// the connection alive. When the timer is triggered, all
			// we need to do is call rtm_poll. It will take care of sending
			// a ping.  We will set the actual timeout below in
			// start_reading().
			m_ping_timer.async_wait([&](const boost::system::error_code& error) {
					(void)error; // unused
					rtm_poll(m_rtm_ptr);
			});

			// At this point RTM has a valid FD. Tell boost::asio to wait for
			// data to become available.
			m_sd.assign(rtm_get_fd(m_rtm_ptr));
			start_reading();

			// If no role is given, we are done. You are now connected to Satori!
			if(!role) {
				m_online = true;
				if(connected_callback)
					connected_callback(true, nullptr);
				return;
			}

			// Perform the handshake. We store the request id and will process the
			// answer below.
			if(rtm_handshake(m_rtm_ptr, role, &m_internal_request_id) != RTM_OK) {
				if(connected_callback)
					connected_callback(false, "Handshake request failed.");
				return;
			}

			// The next steps require us to wait for an answer from the server.
			// Return now, and store the callback and secret.
			m_connected_callback = connected_callback;
			m_secret = secret;
		}

		/**
		 * Subscribe to a channel.
		 *
		 * You must not call this function before you are online.
		 *
		 * \param channel                The name of the channel you want to
		 *                               subscribe to
		 * \param subscription_callback  Callback to call once it is clear
		 *                               whether the call succeeded.
		 * \param message_callback       Callback to call for arriving
		 *                               messages.
		 */
		void subscribe(const char *channel,
				const callback_type &subscription_callback,
				const message_handler_type &message_callback) {
			if(!m_online) {
				if(subscription_callback)
					subscription_callback(false, "Must be online to make a request.");
				return;
			}

			unsigned request_id;
			if(rtm_subscribe(m_rtm_ptr, channel, &request_id) != RTM_OK) {
				if(subscription_callback)
					subscription_callback(false, "Subscription request failed");
				return;
			}

			// Store the user-provided callback in a map, associated with the
			// request_id
			if(subscription_callback)
				m_active_requests[request_id] = subscription_callback;

			// Store the channel handler. RTM uses strings to identify
			// channels, so we can map directly from the name to the callback.
			m_channel_handlers[channel] = message_callback;
		}

		/**
		 * Publish a message to a channel.
		 *
		 * \param channel  The name of a channel
		 * \param json     The message to publish. Must be valid JSON.
		 * \param callback A callback to call once it is clear whether the call
		 *                 succeeded.
		 */
		void publish(const char *channel, const char *json,
				const callback_type &callback) {
			if(!m_online) {
				if(callback)
					callback(false, "Must be online to make a request.");
				return;
			}

			unsigned request_id;
			if(rtm_publish_json(m_rtm_ptr, channel, json, &request_id) != RTM_OK) {
				if(callback)
					callback(false, "Publish request failed.");
				return;
			}

			// Store the user-provided callback in a map, associated with the
			// request_id
			if(callback)
				m_active_requests[request_id] = callback;
		}

		~Rtm() {
			// Termine the Rtm connection
			rtm_close(m_rtm_ptr);
		}

	protected:
		/**
		 * Internal handler for incoming messages. Called by the C API.
		 */
		void handle_pdu(const rtm_pdu_t *pdu) {
			if(pdu->request_id == m_internal_request_id && m_online == false) {
				// This is a reply to once of the handshake/authentication
				// requests.
				switch(pdu->action) {
					case RTM_ACTION_HANDSHAKE_OK:
						// Handshake succeeded. Now authenticate.
						rtm_authenticate(m_rtm_ptr, m_secret.c_str(), pdu->nonce, &m_internal_request_id);
						m_secret.clear();
						return;

					case RTM_ACTION_AUTHENTICATE_OK:
						// Authentication succeeded. Now we are online!
						m_online = true;
						if(m_connected_callback)
							m_connected_callback(true, nullptr);
						return;

					default:
						// We are not interested in other PDUs.
						return;
				}
			}

			// Check whether there is a callback associated with this
			// request_id, and invoke it.
			auto callback_it = m_active_requests.find(pdu->request_id);
			if(callback_it != m_active_requests.end()) {
				bool success = pdu->action == RTM_ACTION_PUBLISH_OK || pdu->action == RTM_ACTION_SUBSCRIBE_OK;
				callback_it->second(success, success ? nullptr : pdu->error);
				m_active_requests.erase(callback_it);
				return;
			}

			// If this is an incoming message for an active subscription,
			// invoke the associated callback.
			if(pdu->action == RTM_ACTION_SUBSCRIPTION_DATA) {
				char *message;
				while((message = rtm_iterate(&pdu->message_iterator))) {
					auto handler_it = m_channel_handlers.find(pdu->subscription_id);
					if(handler_it != m_channel_handlers.end()) {
						handler_it->second(message);
						return;
					}
				}
			}

			// If we have not handled the message so far, use the default
			// handler. It will print the message in a human-readable form to
			// stdout.
			rtm_default_pdu_handler(m_rtm_ptr, pdu);
		}

		/**
		 * Start an asynchronous read call on the Rtm FD using boost::asio.
		 */
		void start_reading() {
			// Tell boost::asio that we want to read from the Rtm FD. By using
			// a null_buffers() instance, we make async_read_some not actually
			// read anything, but still wait with an invocation of our callback
			// until there is data to be read.
			m_sd.async_read_some(boost::asio::null_buffers(),
					boost::bind(&Rtm::handle_read_ready,
						this,
						boost::asio::placeholders::error,
						boost::asio::placeholders::bytes_transferred));

			// Reset the ping timer: Rtm needs to send a "ping" over the
			// WebSocket connection in times of inactivity. Since we just
			// received something, there is no need to send a ping any time
			// soon.
			int seconds = rtm_get_ws_ping_interval(m_rtm_ptr);
			m_ping_timer.cancel();
			m_ping_timer.expires_from_now(boost::posix_time::seconds(seconds));
		}

		/**
		 * Callback invoked by boost::asio once there is some data to be read.
		 */
		void handle_read_ready(const boost::system::error_code& error,
				std::size_t bytes_transferred) {
			(void)bytes_transferred; // unused

			if(error.value() != boost::system::errc::success) {
				// The socket entered an error state
				m_online = false;
				return;
			}

			// Read everything there is to be read from the socket.
			rtm_poll(m_rtm_ptr);

			// We need to tell boost::asio again that we are interested in
			// reading from the socket.
			start_reading();
		}

		rtm_client_t *m_rtm_ptr; //!< Pointer to the C SDK Rtm structure.
		std::vector<char> m_rtm_memory; //!< Memory used by the Rtm structure.
		boost::asio::posix::stream_descriptor m_sd; //!< Wrapper around socket.
		boost::asio::deadline_timer m_ping_timer; //!< Keep-alive timer.
		bool m_online; //!< Whether the connection is up and active.
		unsigned m_internal_request_id; //!< Used in the handshake process.
		std::string m_secret; //!< Stores the user's secret while authenticating

		/**
		 * A map of active requests, indexed by request_id (assigned by C RTM
		 * SDK), mapped to the user callbacks associated with them.
		 */
		std::unordered_map<unsigned, callback_type> m_active_requests;

		/**
		 * A map of active subscriptions, indexed by channel name, mapped to
		 * the user callbacks associated with them.
		 */
		std::unordered_map<std::string, message_handler_type> m_channel_handlers;

		callback_type m_connected_callback; //!< Used after authentication
};

int main() {
	// boost::asio encapsulates asynchronous I/O into io_services. See
	// http://www.boost.org/doc/libs/master/doc/html/boost_asio/ for
	// details.
	boost::asio::io_service io_service;

	// Create RTM instance and let boost::asio handle its file descriptor
	Rtm rtm { io_service };

	// We will send out new messages every few seconds. For simplicity,
	// this is done from a thread here.
	std::thread sender_thread;

	// Connect to RTM. The callback is invoked once the connection succeeded
	// and authentication is done, or once one of the two fails.
	rtm.connect(endpoint, appkey, role, role_secret, [&](bool state, const char *error_message) {
			if(!state) {
				std::cout << "Failed to connect:" << error_message << std::endl;
				return;
			}

			// Subscribe to the "animals" channel.
			rtm.subscribe("animals", [](bool state, const char *error_message) {
					// Called once the subscription was acknowledged.
					if(state)
						std::cout << "Subscribed to animals.\n";
					else
						std::cout << "Failed to subscribe to animals:" << error_message << std::endl;
				}, [](const char *message) {
					// Called when messages arrive on the channel.
					std::cout << "Received animal: " << message << std::endl;
				}
			);

			// Start sending messages every two seconds.
			sender_thread = std::thread([&]() {
					int counter = 0;
					while(true) {
						std::stringstream message;
						message << "\"I am the " << ++counter << ". animal!\"";
						auto message_string = message.str();

						rtm.publish("animals", message_string.c_str(), [](bool state, const char *error_message) {
								if(state)
									std::cout << "Sent out an animal.\n";
								else {
									std::cout << "Failed to send out an animal:" << error_message << std::endl;
									return;
								}
							});
							std::this_thread::sleep_for(std::chrono::seconds(2));
					}
			});
		});

	io_service.run();
	std::cout << "Run exited\n";
}
