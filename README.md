## Simple Instruction-level debugger

### Project structure
* /cpp-server - The debugger itself. Written in C++.
* /kotlin-client - Client part. CLI from which all the interactions with take place. Written in Kotlin.
* /cpp-server/tests - Unit tests.
  
### Dependencies
* kotlin
* libcapstone-dev
* libboost-all-dev
* libgtest-dev

### How to build
debugger
```
mkdir build && cd build
cmake ../cpp-server
make
```
client
```
cd kotlin-client
./build.sh .
```

### Usage
1. Run debugger: `./debugger <program> <port>`
2. Connect client: `java -jar Client.jar <server> <port>`
3. Debug assembly using available commands:
```
break <address>
break <function_name>
continue/c
step/s
step over
step out
state
exit
```
    
