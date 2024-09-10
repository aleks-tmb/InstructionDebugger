#ifndef SERVERDEBUGGER_H
#define SERVERDEBUGGER_H

#include "debugger.h"

#include <boost/asio.hpp>

namespace debugger {

class ServerDebugger
{
public:
  ServerDebugger(boost::asio::io_context& io_context, short port, Debugger& debugger);

private:
  void do_accept(Debugger& debugger);
  boost::asio::ip::tcp::acceptor acceptor_;
};

} // namespace debugger

#endif // SERVERDEBUGGER_H
