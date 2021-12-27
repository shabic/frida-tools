import { log } from "./log";

export function hookRegisterNatives(callback) {
  var addrRegisterNatives = null;
  {
    for (let sym of Module.enumerateSymbolsSync("libart.so")) {
      //_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
      if (
        sym.name.indexOf("art") >= 0 &&
        sym.name.indexOf("JNI") >= 0 &&
        sym.name.indexOf("RegisterNatives") >= 0 &&
        sym.name.indexOf("CheckJNI") < 0
      ) {
        addrRegisterNatives = sym.address;
        console.log("RegisterNatives is at ", sym.address, sym.name);
        break;
      }
    }

    if (addrRegisterNatives == null) {
      log("can not find RegisterNatives");
      return;
    }
  }

  /**
  * typedef struct {
      const char* name;
      const char* signature;
      void*       fnPtr;
    } JNINativeMethod

    jint RegisterNatives(jclass clazz, const JNINativeMethod* methods, jint nMethods){
	    return functions->RegisterNatives(this, clazz, methods, nMethods);
    }
  */
  Interceptor.attach(addrRegisterNatives, {
    onEnter: function (args) {
      console.log("[RegisterNatives] method_count:", args[3]);
      var class_name = Java.vm.tryGetEnv().getClassName(args[1]);

      var methods = ptr(args[2]);

      for (var i = 0; i < parseInt(args[3]); i++) {
        var namePtr = methods.add(i * Process.pointerSize * 3).readPointer();

        var sigPtr = methods
          .add(i * Process.pointerSize * 3 + Process.pointerSize)
          .readPointer();

        var fnPtr = methods
          .add(i * Process.pointerSize * 3 + Process.pointerSize * 2)
          .readPointer();

        callback(
          class_name,
          namePtr.readCString(),
          sigPtr.readCString(),
          fnPtr,
          Process.findModuleByAddress(fnPtr)
        );
      }
    },
  });
}
