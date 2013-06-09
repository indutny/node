#include "node_wrap.h"

namespace node {

using namespace v8;

Persistent<FunctionTemplate> pipeConstructorTmpl;
Persistent<FunctionTemplate> ttyConstructorTmpl;
Persistent<FunctionTemplate> tcpConstructorTmpl;
Persistent<FunctionTemplate> udpConstructorTmpl;

} // namespace node
