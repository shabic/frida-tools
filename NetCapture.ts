import { log } from "./log";

const String = Java.use("java.lang.String");

/**
 * 捕获http请求
 */
export function captureHttpRequest() {
  Java.use("java.net.SocketOutputStream").socketWrite0.overload(
    "java.io.FileDescriptor",
    "[B",
    "int",
    "int"
  ).implementation = function (
    fd: any,
    bytearry: any,
    offset: number,
    byteCount: number
  ) {
    var result = this.socketWrite0(fd, bytearry, offset, byteCount);
    log("===========================request=============================");
    log(String.$new(bytearry, offset, byteCount));
    return result;
  };
}

/**
 * 捕获http响应
 */
export function captureHttpResponse() {
  Java.use("java.net.SocketInputStream").socketRead0.overload(
    "java.io.FileDescriptor",
    "[B",
    "int",
    "int",
    "int"
  ).implementation = function (
    fd: any,
    bytearry: any,
    offset: number,
    byteCount: number,
    timeout: number
  ) {
    var result = this.socketRead0(fd, bytearry, offset, byteCount, timeout);
    log("============================response============================");
    log(String.$new(bytearry, offset, byteCount));
    return result;
  };
}
