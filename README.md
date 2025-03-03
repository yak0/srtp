# srtp

Experimental SRTP implementation in C with Copilot / Claude 3.7 (preview)

## Overview

This is an experimental project with no clear goal—I'm just exploring the limits of AI models that generate code.

I was curious about how well an AI model could implement a protocol. After a few prompts, I got this result. I haven't tested it yet, but I tried to cover as many cases as possible by writing a detailed prompt, which I even created with the help of the model.

## Comparison

To understand how good it is, I compared it to [Cisco's libsrtp implementation](https://github.com/cisco/libsrtp/blob/main/srtp/srtp.c). The model also listed the missing parts:

1. **Stream Management System** - No proper handling of multiple concurrent streams
2. **SRTP Context Structure** - Lacks a comprehensive context structure for maintaining state
3. **Complete Error Handling System** - Missing robust error detection and reporting
4. **Proper RTCP Support** - RTCP packet processing is incomplete
5. **Extensions Support** - No implementation for header extensions
6. **Profiling Support** - Missing performance profiling capabilities
7. **Thread Safety** - Improvements beyond basic mutex usage
8. **Hardware Acceleration** - Support for cryptographic operations
9. **SRTCP Support** - More comprehensive RTCP implementation and SRTCP validation
10. **Advanced Cryptography** - Additional cipher suite support (AES-256, AES-GCM, etc.)
11. **Security Hardening** - Memory hardening to protect against side-channel attacks
12. **Input Validation** - Comprehensive validation of packet structure before processing