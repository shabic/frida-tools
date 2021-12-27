/**
 * 反编译内存地址代码
 * @param address 内存地址
 * @param line 反汇编输出行数
 */
export function disam(address: NativePointer, line: number) {
  for (let index = 0; index < line; index++) {
    let ins = Instruction.parse(address);
    var hexstr = "";
    new Uint8Array(ins.address.readByteArray(ins.size)!).forEach((value) => {
      var hex = (value & 0xff).toString(16);
      hex = hex.length === 1 ? "0" + hex : hex;
      hexstr += " " + hex;
    });

    console.log(ins.address, hexstr, ins.size === 2 ? "\t" : "", ins);
    address = ins.next;
  }
}
