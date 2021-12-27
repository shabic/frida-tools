export function log(message?: any, ...optionalParams: any[]) {
  console.log(message, optionalParams);
}

/**
 *
 * @param context 上下文
 * @param backtracer 模糊、精确
 */
export function printNativeBacktrace(
  context?: CpuContext,
  backtracer: Backtracer = Backtracer.ACCURATE
) {
  log(
    "CCCryptorCreate called from:\n" +
      Thread.backtrace(context, backtracer)
        .map(DebugSymbol.fromAddress)
        .join("\n") +
      "\n"
  );
}

export function printJavaBacktrace() {
  log(
    Java.use("android.util.Log")
      .getStackTraceString(Java.use("java.lang.Throwable").$new())
      .toString()
      .replace("java.lang.Throwable\n", "")
  );
}
