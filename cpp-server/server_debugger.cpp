#include "server_debugger.h"

#include <iostream>

namespace debugger {

using boost::asio::ip::tcp;

class Session : public std::enable_shared_from_this<Session> {
public:
  Session(tcp::socket socket, Debugger& debugger) : socket_(std::move(socket)), debugger_(debugger) {}

  void start() { do_read(); }

private:
  const std::string END = "END";

  void do_read() {
    auto self(shared_from_this());
    socket_.async_read_some(boost::asio::buffer(data_, max_length),
        [this, self](boost::system::error_code ec, std::size_t length) {
          if (!ec) {
            std::string request(data_, length);
            // Remove "END" from the request if it exists
            std::size_t end_pos = request.find(END);
            if (end_pos != std::string::npos) {
              request.erase(end_pos, END.length());
            } else {
              std::cerr << "Error: END delimiter not found. Dropping the message." << std::endl;
              return;
            }

            // Remove any trailing newlines
            request.erase(std::remove(request.begin(), request.end(), '\n'), request.end());
            request.erase(std::remove(request.begin(), request.end(), '\r'), request.end());

            std::string response = debugger_.handle_command(request);
            do_write(response);
          }
        });
  }

  void do_write(std::string& reply) {
      auto self(shared_from_this());
      
      // Buffers for reply and the END delimiter
      std::array<boost::asio::const_buffer, 2> buffers = {
          boost::asio::buffer(reply),
          boost::asio::buffer(END, sizeof(END)-1)
      };

      // Send both buffers in a single operation
      boost::asio::async_write(socket_, buffers,
          [this, self](boost::system::error_code ec, std::size_t /*length*/) {
              if (!ec) {
                  do_read();
              }
          });
  }

  Debugger& debugger_;
  tcp::socket socket_;
  enum { max_length = 1024 };
  char data_[max_length];
};

ServerDebugger::ServerDebugger(boost::asio::io_context& io_context, short port, Debugger& debugger)
    : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)) {
  do_accept(debugger);
}

void ServerDebugger::do_accept(Debugger& debugger) {
  acceptor_.async_accept(
      [this, &debugger](boost::system::error_code ec, tcp::socket socket) {
        if (!ec) {
          std::make_shared<Session>(std::move(socket), debugger)->start();
        }
      });
}
} // namespace debugger
