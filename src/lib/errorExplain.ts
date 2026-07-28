export function explainError(message: string, language: "zh" | "en") {
  const lower = message.toLowerCase();
  const zh = language === "zh";
  const result: string[] = [];

  const add = (cn: string, en: string) => result.push(zh ? cn : en);

  if (/token length exception/.test(lower)) {
    add("hash 长度或格式与当前 -m 类型不匹配。优先检查 hash 类型、是否多了用户名字段、是否复制完整。", "Hash length or format does not match the selected -m mode. Check hash type, username fields, and whether the hash is complete.");
  }
  if (/separator unmatched|separator/.test(lower)) {
    add("分隔符不匹配，通常是 hash 格式选错，或输入里包含 hashcat 当前模式不接受的冒号字段。", "Separator mismatch. The selected hash mode may not match the colon-separated format.");
  }
  if (/no hashes loaded|hashfile/.test(lower)) {
    add("hashcat 没有加载到有效 hash。检查 hash 文件/粘贴内容、hash 类型和文件编码。", "hashcat did not load valid hashes. Check the hash file/text, selected mode, and file encoding.");
  }
  if (/no devices found|device|cuda|opencl|hip|vulkan/.test(lower)) {
    add("可能是设备或驱动问题。尝试扫描设备，或切换 CPU/GPU 类型和设备编号。", "This may be a device or driver issue. Scan devices, or adjust CPU/GPU type and device IDs.");
  }
  if (/cl_out_of_resources|out of memory|insufficient memory|memory/.test(lower)) {
    add("可能是显存/内存不足。降低性能模式、减少设备压力，或换更小的攻击范围。", "This may be VRAM/RAM pressure. Lower workload, reduce device load, or shrink the attack range.");
  }
  if (/exhausted/.test(lower)) {
    add("任务正常跑完但没有破解。下一步应调整 hash 类型、mask、字典或规则，而不是直接重复同一配置。", "The task completed but found nothing. Adjust hash mode, mask, dictionary, or rules instead of rerunning the same config.");
  }
  if (/access is denied|permission denied/.test(lower)) {
    add("文件权限不足。检查 hashcatGUI 所在目录、hash 文件、字典文件是否可读写。", "Permission denied. Check whether the tool folder, hash file, and dictionary are readable/writable.");
  }

  return [...new Set(result)].slice(0, 3);
}
