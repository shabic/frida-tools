import { SyscallCallback } from "./callback";
import { disam } from "./Instruction";

/**
 * 系统调用查找
 * @param filter 过滤查找的range
 * @param callback 查找回调
 */
export function findSyscall(
  filter: (range: RangeDetails) => boolean,
  callback: (address: NativePointer, callNumber: number, file: string) => void
) {
  let pattern = "";
  switch (Process.arch) {
    case "arm":
      //svc 0
      pattern = "00 00 00 ef";
      break;
    case "arm64":
      pattern = "01 00 00 d4";
      break;
    default:
      console.log("not support ", Process.arch);
      return;
  }

  Process.enumerateRanges("--x").forEach((range) => {
    if (!filter(range)) return;

    Memory.scan(range.base, range.size, pattern, {
      onMatch: (address) => {
        if (
          address.toString().endsWith("0") ||
          address.toString().endsWith("4") ||
          address.toString().endsWith("8") ||
          address.toString().endsWith("c")
        ) {
          let callNumber = -1;

          if (Process.arch == "arm") {
            callNumber = address.sub(0x4).readS32() & 0xfff;
          } else if (Process.arch == "arm64") {
            callNumber = (address.sub(0x4).readS32() >> 5) & 0xffff;
          } else {
            console.log("not support ", Process.arch);
          }

          callback(address, callNumber, range.file?.path!);
        }
      },
      onError: (reason) => {
        console.error(reason);
      },
      onComplete: () => {},
    });
  });
}

let callbacks: SyscallCallback[] = [];

export function hookSyscall(
  syscallAddress: NativePointer,
  callback: NativeCallback<any, any>
) {
  if (Process.arch == "arm") {
    const address = syscallAddress.sub(8);
    const instructions = address.readByteArray(20);

    if (instructions == null) {
      throw new Error(`Unable to read instructions at address ${address}.`);
    }

    console.log(" ==== old instructions ==== " + address);
    console.log(instructions);

    Memory.patchCode(address, 20, function (code) {
      let writer = null;

      writer = new ArmWriter(code, { pc: address });
      writer.putBranchAddress(
        createCallback(callback, instructions, address.add(20), syscallAddress)
      );
      writer.flush();
    });

    console.log(" ==== new instructions ==== " + address);
    const instructionsNew = address.readByteArray(20);
    console.log(instructionsNew);
  } else {
    const address = syscallAddress.sub(12);
    const instructions = address.readByteArray(12);

    if (instructions == null) {
      throw new Error(`Unable to read instructions at address ${address}.`);
    }

    console.log(" ==== old instructions ==== " + address);
    console.log(instructions);

    Memory.patchCode(address, 16, function (code) {
      let writer = null;

      writer = new Arm64Writer(code, { pc: address });
      writer.putBranchAddress(
        createCallback(callback, instructions, address.add(16), syscallAddress)
      );

      writer.flush();
    });

    console.log(" ==== new instructions ==== " + address);
    const instructionsNew = address.readByteArray(12);
    console.log(instructionsNew);
  }
}

function createCallback(
  callback: NativeCallback<any, any>,
  instructions: ArrayBuffer,
  retAddress: NativePointer,
  syscallAddress: NativePointer
) {
  // Create custom instructions.
  let frida = Memory.alloc(Process.pageSize);

  Memory.patchCode(frida, Process.pageSize, function (code) {
    let writer = null;
    if (Process.arch == "arm") {
      /*
       * Created by fenfei
       * http://91fans.com.cn/
       * public accounts: fenfei330
       * wx:fenfei331  mail:fenfei331@126.com
       */

      writer = new ArmWriter(code, { pc: frida });

      // Restore argument instructions.
      writer.putBytes(instructions);

      // FE 5F 2D E9 STMFD  SP!, {R1-R12,LR} 寄存器入栈 不存 r0
      // FF 5F 2D E9 STMFD  SP!, {R0-R12,LR} 寄存器入栈
      writer.putInstruction(0xe92d5fff);
      // 00 A0 0F E1 MRS R10, CPSR
      // 00 04 2D E9 STMFD SP!, {R10}    // 状态寄存器入栈
      writer.putInstruction(0xe10fa000);
      writer.putInstruction(0xe92d0400);

      // instructions.size = 20  + 5条指令
      writer.putLdrRegAddress("lr", frida.add(20 + 5 * 4));
      writer.putBImm(callback);

      // 00 04 BD E8  LDMFD SP!, {R10}   // 状态寄存器出栈
      // 0A F0 29 E1  MSR CPSR_cf, R10
      writer.putInstruction(0xe8bd0400);
      writer.putInstruction(0xe129f00a);

      // FE 9F BD E8 LDMFD  SP!, {R1-R12,PC}    寄存器出栈 不存 r0
      // FF 5F BD E8 LDMFD  SP!, {R0-R12,LR}    寄存器出栈
      writer.putInstruction(0xe8bd5fff);
    } else {
      writer = new Arm64Writer(code, { pc: frida });

      // Restore argument instructions.
      writer.putBytes(instructions);

      // Push all registers except x0.
      writer.putPushRegReg("x15", "x1");
      writer.putPushRegReg("x2", "x3");
      writer.putPushRegReg("x4", "x5");
      writer.putPushRegReg("x6", "x7");
      writer.putPushRegReg("x8", "x9");
      writer.putPushRegReg("x10", "x11");
      writer.putPushRegReg("x12", "x13");
      writer.putPushRegReg("x14", "x15");
      writer.putPushRegReg("x16", "x17");
      writer.putPushRegReg("x18", "x19");
      writer.putPushRegReg("x20", "x21");
      writer.putPushRegReg("x22", "x23");
      writer.putPushRegReg("x24", "x25");
      writer.putPushRegReg("x26", "x27");
      writer.putPushRegReg("x28", "x29");
      writer.putInstruction(0xd53b420f); // 保存状态寄存器
      writer.putPushRegReg("x30", "x15");

      // Call native.
      writer.putLdrRegAddress("x16", callback);
      writer.putBlrReg("x16");

      // Pop all registers, except x0, so x0 from native call gets used.
      writer.putPopRegReg("x30", "x15");
      writer.putInstruction(0xd51b420f); // 还原状态寄存器
      writer.putPopRegReg("x28", "x29");
      writer.putPopRegReg("x26", "x27");
      writer.putPopRegReg("x24", "x25");
      writer.putPopRegReg("x22", "x23");
      writer.putPopRegReg("x20", "x21");
      writer.putPopRegReg("x18", "x19");
      writer.putPopRegReg("x16", "x17");
      writer.putPopRegReg("x14", "x15");
      writer.putPopRegReg("x12", "x13");
      writer.putPopRegReg("x10", "x11");
      writer.putPopRegReg("x8", "x9");
      writer.putPopRegReg("x6", "x7");
      writer.putPopRegReg("x4", "x5");
      writer.putPopRegReg("x2", "x3");
      writer.putPopRegReg("x15", "x1");
    }

    // Call syscall.
    // writer.putInstruction(0xd4000001);

    writer.putBranchAddress(retAddress);
    writer.flush();
  });

  console.log("==== frida ====");
  console.log(frida);

  console.log("==== retAddress ====");
  console.log(retAddress);

  // Store callback so it doesn't get garbage collected.
  callbacks.push(new SyscallCallback(frida, callback));

  // Return pointer to the instructions.
  return callbacks[callbacks.length - 1].frida;
}

export function hook(
  address: NativePointer,
  callback: NativeCallback<any, any>
) {
  disam(address, 10);
  const frida = Memory.alloc(Process.pageSize);
  Memory.patchCode(address, 20, function (code) {
    var aw = new ArmWriter(code, { pc: address });
    aw.putBranchAddress(frida);
    aw.flush();
  });

  console.log("------", frida);
  disam(address, 20);
}
