import { Component, useEffect, useMemo, useRef, useState, useCallback, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { invoke } from "@tauri-apps/api/core";
import { listen, type Event, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open, save } from "@tauri-apps/plugin-dialog";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  AlertTriangle,
  Bot,
  Activity,
  Copy,
  Cpu,
  Download,
  FileClock,
  FileText,
  FolderOpen,
  Hash,
  HelpCircle,
  History,
  Library,
  Play,
  RefreshCcw,
  Settings,
  ShieldCheck,
  Sparkles,
  Square,
  Terminal,
  Thermometer,
  Trash2,
  Zap,
  X,
  ChevronDown,
  ChevronUp,
  ArrowUpToLine,
  ArrowDownToLine,
  Plus,
  Edit3,
  Info,
  Sliders,
  FolderPlus,
  FolderOutput,
  ChevronRight,
} from "lucide-react";
import { AboutDialog } from "./components/AboutDialog";
import { UpdateDialog } from "./components/UpdateDialog";
import { Notice } from "./components/Notice";
import { ZH_TEXT_OVERRIDES } from "./i18n/zhText";
import { explainError } from "./lib/errorExplain";
import { getCurrentWindow  } from "@tauri-apps/api/window";
import pkg from "../package.json";
import "./App.css";

type AttackMode = 0 | 1 | 3 | 6 | 7 | 9;
type TabKey = "config" | "resources" | "queue" | "history";
type Language = "zh" | "en";

// 单条 hash 记录
type Hc22000Entry = {
  essid: string;
  bssid: string;
  apMac: string;
  lineText: string;
};

// .hc22000 文件解析结果
type Hc22000Info = {
  entries: Hc22000Entry[];  // 支持多条记录
  lineCount: number;         // 总行数
};

type LineCountResult = {
  count: number;
  is_estimated: boolean;
};

type PresetConfig = {
  id: string;
  name: string;
  description: string;
  attackMode: AttackMode;  // 0|1|3|6|7|9
  hashMode?: string;
  dictionaryPaths?: string[];
  dictionaryPath?: string;
  dictionaryPath2?: string;
  mask?: string;
  maskPath?: string;
  prefixMask?: string;
  suffixMask?: string;
  useRules?: boolean;
  useLeftRule?: boolean;
  leftRule?: string;
  useRightRule?: boolean;
  rightRule?: string;
  customCharsets?: Record<string, string>;
  increment?: boolean;
  incrementMin?: string;
  incrementMax?: string;
  rulePaths?: string[];
  createdAt: string;
  candidates?: string;
  isEstimated?: boolean;
  detailDisplay?: string;
  isValid?: boolean;
};

type PresetGroup = {
  id: string;
  name: string;
  presetIds: string[];
  expanded: boolean;
};

interface ValidationParams {
  attackMode: AttackMode;
  hashMode?: string;
  hashText?: string;
  hashFile?: string;
  dictionaryPath?: string;
  dictionaryPath2?: string;
  dictionaryPaths?: string[];
  mask?: string;
  maskFile?: string;
  templatePrefixMask?: string;
  templateSuffixMask?: string;
  requireHash?: boolean;
}

interface ImportPreviewData {
  version: string;
  type: string;
  group_count: number;
  item_count: number;
  groupCount?: number;
  itemCount?: number;
  groups: Array<{
    id: string;
    name: string;
    item_count: number;
    itemCount?: number;
  }>;
}

interface ImportResult {
  success: boolean;
  message: string;
  imported_groups: number;
  imported_items: number;
}

type ImportMode = 'merge' | 'overwrite' | 'skip';

interface ConflictInfo {
    id: string;
    name: string;
    type: 'preset' | 'group';
    existingName?: string;
    groupId?: string;    // 新增：预设所属的分组ID
    groupName?: string;  // 新增：预设所属的分组名称
}

interface ImportPreviewResult {
    success: boolean;
    message: string;
    importedGroups: number;
    importedItems: number;
    conflicts: ConflictInfo[];
}

function validateAttackConfig(params: ValidationParams, text: UiText): { valid: boolean; error?: string } {
  // 检查 hash（根据参数决定是否必需）
  if (params.requireHash !== false) {
    const hasHash = (params.hashText?.trim().length || 0) > 0 || (params.hashFile?.trim().length || 0) > 0;
    if (!hasHash) return { valid: false, error: text.missingHash };
  }
  
  // 检查 hashMode（预设不需要强制校验）
  if (params.requireHash !== false && !params.hashMode?.trim()) {
    return { valid: false, error: text.missingHashMode };
  }
  
  // 根据攻击模式检查必要配置
  switch (params.attackMode) {
    case 0: // 字典攻击 - 需要字典
      if (!((params.dictionaryPath?.trim().length || 0) > 0 || (params.dictionaryPaths?.length || 0) > 0)) {
        return { valid: false, error: text.missingDictionary };
      }
      break;
    case 1: // 组合攻击
      if (!((params.dictionaryPath?.trim().length || 0) > 0 && (params.dictionaryPath2?.trim().length || 0) > 0)) {
        return { valid: false, error: text.missingDictionary2 };
      }
      break;
    case 3: // 掩码攻击 - 需要掩码或掩码文件
      if (!((params.mask?.trim().length || 0) > 0 || (params.maskFile?.trim().length || 0) > 0)) {
        return { valid: false, error: text.missingMask };
      }
      break;
    case 6: // 混合字典+掩码
    case 7: // 混合掩码+字典
      if (!((params.dictionaryPath?.trim().length || 0) > 0 && ((params.mask?.trim().length || 0) > 0 || (params.maskFile?.trim().length || 0) > 0))) {
        return { valid: false, error: text.missingDictOrMask };
      }
      break;
    case 9: // 模板攻击
      if (!((params.templatePrefixMask?.trim().length || 0) > 0 || (params.templateSuffixMask?.trim().length || 0) > 0)) {
        return { valid: false, error: text.missingTemplate };
      }
      break;
  }
  return { valid: true };
}

type HashcatInfo = {
  available: boolean;
  version?: string | null;
  hashcatPath?: string | null;
  resourceRoot?: string | null;
  backendInfo?: Record<string, unknown> | null;
  backendRaw?: string;
  error?: string | null;
};

type HashcatPathStatus = {
  customInstallDir?: string | null;
  effectiveDir?: string | null;
  effectiveExe?: string | null;
  usingCustom: boolean;
  available: boolean;
};

type HashModeInfo = {
  mode: number;
  name: string;
  category: string;
  keywords: string[];
};

type ResourceInfo = {
  kind: "rule" | "mask" | "charset" | "dictionary";
  name: string;
  path: string;
  size: number;
  candidates?: number;
  isEstimated?: boolean;
  isValid?: boolean;
};

type UserDictionary = {
  name: string;
  path: string;
  size: number;
  addedAt: string;
  candidates?: number;
  isEstimated?: boolean;
  isValid?: boolean;
};

type CustomResource = {
  id: string;
  type: "mask" | "template" | "dictionary" | "charset" | "rule";
  name: string;
  description: string;
  mask?: string;
  prefixMask?: string;
  suffixMask?: string;
  charsetSlot?: "1" | "2" | "3" | "4";
  charsetValue?: string;
  path?: string;
  size?: number;
  createdAt: string;
  candidates?: number;
  isBuiltinCopy?: boolean;
  ruleType?: "left" | "right";
  ruleValue?: string;
  sortOrder?: number;
  isValid?: boolean;
};

type AttackConfig = {
  hashMode: string;
  attackMode: AttackMode;
  hashText?: string | null;
  hashFile?: string | null;
  dictionaryPath?: string | null;
  dictionaryPath2?: string | null;
  dictionaryPaths?: string[];
  useRules?: boolean;        // 新增
  useLeftRule?: boolean;     // 新增
  useRightRule?: boolean;    // 新增
  leftRule?: string | null;   // 新增：左规则字符串
  rightRule?: string | null;  // 新增：右规则字符串
  mask?: string | null;
  maskFile?: string | null;
  templatePrefixMask?: string | null;
  templateSuffixMask?: string | null;
  increment?: boolean | null;
  incrementMin?: number | null;
  incrementMax?: number | null;
  customCharset1?: string | null;
  customCharset2?: string | null;
  customCharset3?: string | null;
  customCharset4?: string | null;
  charsetFile1?: string | null;
  charsetFile2?: string | null;
  charsetFile3?: string | null;
  charsetFile4?: string | null;
  rulePaths: string[];
  taskName?: string | null;
  optimizedKernel?: boolean | null;
  workloadProfile?: number | null;
  deviceTypes: string[];
  deviceIds?: string | null;
  candidates?: bigint | number;
  isEstimated?: boolean;
};

type AttackSequenceItem = {
  id: string;
  config: AttackConfig;
  candidates?: bigint;
  isEstimated?: boolean;
};

type QueueStatus = "pending" | "running" | "finished" | "failed" | "skipped" | "stopped";

type QueueItem = {
  id: string;
  name: string;
  config: AttackConfig;
  status: QueueStatus;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  taskId?: string;
  error?: string;
  progress?: [number, number];
  estimatedStop?: number;
  candidates?: bigint;
  isEstimated?: boolean;
  groupId?: string;
  hashContent?: string;
};

type StatusPayload = {
  taskId: string;
  data: Record<string, unknown>;
};

type TaskManifest = {
  taskId: string;
  taskName: string;
  createdAt: string;
  startedAt: string;
  endedAt?: string;
  status: string;
  exitCode?: number | null;
  exitReason?: string | null;
  canRestore: boolean;
  commandPreview: string;
  config: AttackConfig;
  paths: {
    taskDir: string;
    outfilePath: string;
    potfilePath?: string;
    logPath: string;
  };
  extractedPasswords?: string[] | null;
  passwordsExtracted?: boolean;
};

type StartResponse = {
  taskId: string;
  commandPreview: string;
  outfilePath: string;
};

type LogPayload = {
  taskId: string;
  stream: string;
  line: string;
};

type ExitPayload = {
  taskId: string;
  code?: number | null;
  reason: string;
};

type ResultsResponse = {
  path: string;
  content: string;
};

type FilePreviewResponse = {
  path: string;
  content: string;
  truncated: boolean;
  lineCount: number;
  fileSize: number;
  previewLimit: number;
};

type DictionaryDedupeResponse = {
  path: string;
  originalLines: number;
  uniqueLines: number;
  removedLines: number;
  size: number;
};

type AiSettings = {
  baseUrl: string;
  apiKey: string;
  model: string;
};

type AiModelsResponse = {
  models: string[];
};

type AiHashConsultConfig = {
  hashMode: string;
  attackMode: AttackMode;
  hashText?: string;
  hashFile?: string;
  mask?: string;
  dictionaryPath?: string;
  rulePaths: string[];
  question: string;
};

type AiSuggestedConfig = Partial<{
  hashMode: string;
  attackMode: AttackMode;
  hashText: string;
  hashFile: string;
  mask: string;
  dictionaryPath: string;
  rulePaths: string[];
}>;

type AiAnalysisEvent = {
  taskId: string;
  text?: string;
  error?: string;
};

type HashcatUpdateInfo = {
  currentVersion?: string | null;
  latestVersion: string;
  latestName: string;
  assetName: string;
  assetUrl: string;
  releaseUrl: string;
  upToDate: boolean;
};

type HashcatUpdateEvent = {
  phase: string;
  line: string;
};

type HashcatUpdateFinishEvent = {
  ok: boolean;
  info?: HashcatUpdateInfo | null;
  error?: string | null;
};

type MaskEstimate = {
  candidates?: bigint;
  estimatedSeconds?: number;
  speedHps?: number;
  warning?: string;
  error?: string;
};

type HashModeSuggestion = {
  mode: string;
  name: string;
  reason: string;
  confidence: "high" | "medium" | "low";
};

type IdentifyResponse = {
  raw: string;
  modes: HashModeInfo[];
};

type DialogErrorBoundaryProps = {
  fallback: string;
  children: ReactNode;
};

type DialogErrorBoundaryState = {
  error: string;
};

class DialogErrorBoundary extends Component<DialogErrorBoundaryProps, DialogErrorBoundaryState> {
  state: DialogErrorBoundaryState = { error: "" };

  static getDerivedStateFromError(error: unknown) {
    return { error: String(error) };
  }

  render() {
    if (this.state.error) {
      return (
        <div className="modal-backdrop" role="presentation">
          <section className="settings-modal" role="dialog" aria-modal="true">
            <div className="settings-test warn">{this.props.fallback}: {this.state.error}</div>
          </section>
        </div>
      );
    }
    return this.props.children;
  }
}

const TABS: Array<{ key: TabKey; icon: ReactNode }> = [
  { key: "config", icon: <Terminal size={18} /> },
  { key: "queue", icon: <FileClock size={18} /> },
  { key: "history", icon: <History size={18} /> },
  { key: "resources", icon: <Library size={18} /> },
];

const LANGUAGE_STORAGE_KEY = "hashcatgui-language";
const FIRST_GUIDE_STORAGE_KEY = "hashcatgui-first-guide-dismissed";
const TASK_QUEUE_STORAGE_KEY = "hashcatgui-task-queue";
const TASK_NAMES_STORAGE_KEY = "hashcatgui-task-names";
const TASK_CANDIDATES_STORAGE_KEY = "hashcat-task-candidates";
const SIMPLE_MODE_STORAGE_KEY = "hashcatgui-simple-mode";
const ADVANCED_SETTINGS_STORAGE_KEY = "hashcatgui-advanced-settings"
const isTauriRuntime = typeof window !== "undefined"
  && Boolean((window as any).__TAURI__ || (window as any).__TAURI_INTERNALS__);

async function tauriListen<T>(eventName: string, handler: (event: Event<T>) => void | Promise<void>) {
  if (!isTauriRuntime) {
    return () => undefined;
  }
  return listen<T>(eventName, handler);
}

const UI_TEXT = {
  zh: {
    appReady: "Ready",
    appMissing: "Missing",
    taskHealth: "任务",
    taskBusy: "努力中",
    taskIdle: "休息中",
    settingsTitle: "设置",
    helpTitle: "帮助",
    aboutTitle: "关于",
    advancedSettings: "高级",
    helpSubtitle: "攻击教程与 AI 咨询",
    attackTutorials: "攻击方式速查",
    aiHashAdvisor: "询问 AI",
    helpDictionaryTitle: "字典攻击 -a 0 / -a 1",
    helpDictionaryBody: "用字典里的候选密码逐个尝试，适合已知密码可能来自常见词、泄露密码、姓名、手机号片段等场景。可以叠加规则文件 -r 批量变形。",
    helpMaskTitle: "掩码攻击 -a 3",
    helpMaskBody: "用 ?d、?l、?u、?s 等字符集枚举固定结构。例如 2015?d?d?d?d 会尝试 20150000 到 20159999。",
    helpHybridTitle: "混合攻击 -a 6 / -a 7",
    helpHybridBody: "-a 6 是 字典词 + 掩码，例如 admin?d?d；-a 7 是 掩码 + 字典词，例如 ?d?dadmin。",
    helpTemplateTitle: "模板候选",
    helpTemplateBody: "适合 ?d?d + 字典词 + ?d?d 这类中间夹字典词的结构。工具会先生成临时候选字典，再用 -a 0 破解。",
    helpRuleTitle: "规则攻击",
    helpRuleBody: "规则只配合字典攻击使用，用来把字典词自动变形，例如首字母大写、末尾追加数字、替换字符等。",
    aiQuestion: "你的问题",
    aiQuestionPlaceholder: "例如：这个 hash 看起来像什么类型？现在的 mask 是否合理？下一步应该怎么跑？",
    useCurrentConfig: "已带入当前任务配置",
    chooseHashTxt: "选择 hash.txt",
    askAi: "询问 AI",
    aiThinking: "AI 分析中",
    aiAnswer: "AI 回答",
    aiStartedInWindow: "AI 分析已在独立窗口后台运行，可以最小化或继续操作主界面。",
    applyAiSuggestion: "应用到任务",
    noAiSuggestion: "AI 结果里没有可应用的任务配置。",
    aiSuggestionApplied: "已根据 AI 建议填充任务配置。",
    refresh: "刷新",
    hashcatUpdate: "Hashcat 更新",
    hashcatUpdateHint: "检查 GitHub 官方发布，安装到工具目录 resources/hashcat-current；内置 hashcat 保留为备用。",
    checkUpdate: "检查更新",
    installUpdate: "更新 hashcat",
    updateCurrent: "当前版本",
    updateLatest: "最新版本",
    updatePackage: "发布包",
    updateUpToDate: "已经是最新版本",
    updateAvailable: "发现新版本",
    updateNotChecked: "尚未检查",
    updateRunning: "更新中",
    updateLog: "更新回显",
    openRelease: "打开发布页",
    tabConfig: "任务",
    tabResources: "资源",
    tabHistory: "历史",
    tabLogs: "日志",
    attackConfigTitle: "任务配置",
    attackSettings: "攻击设置",
    addToSequence: "加入攻击序列",
    attackSequence: "攻击序列",
    dictionary: "字典",
    dictionaryCombo: "字典组合",
    leftRule: "左规则",
    rightRule: "右规则",
    rulePlaceholder: "输入规则字符串，如：$0$1$2",
    mask: "掩码",
    hybridDictMask: "字典+掩码",
    hybridMaskDict: "掩码+字典",
    templateAttack: "候选模板",
    prefixMask: "前缀掩码",
    suffixMask: "后缀掩码",
    templateHint: "生成：前缀掩码 + 字典词 + 后缀掩码，再用 -a 0 破解。",
    templatePreviewWord: "字典词",
    start: "启动",
    stop: "停止",
    attackControl: "攻击控制",
    taskName: "任务名",
    taskNamePlaceholder: "可选，便于历史中识别",
    hashMode: "Hash 模式",
    hashModePlaceholder: "例如 0 / 1000 / 1400",
    workload: "负载",
    performanceMode: "性能模式",
    deviceControl: "设备性能",
    deviceControlHint: "选择 CPU/GPU、指定设备编号，并实时观察速度、温度、利用率和显存。",
    scanDevices: "扫描设备",
    deviceTypes: "设备类型",
    cpuDevice: "CPU",
    gpuDevice: "GPU",
    deviceIds: "设备编号",
    deviceIdsPlaceholder: "例如 1 或 1,2；留空为 hashcat 自动选择",
    noDeviceStatus: "任务运行后显示实时设备状态。",
    backendDeviceInfo: "后端设备信息",
    backendRawSummary: "原始摘要",
    deviceIdLabel: "设备编号",
    deviceMemory: "内存",
    deviceBackend: "后端",
    deviceVendor: "厂商",
    deviceProcessor: "处理器",
    deviceScanReady: "点击扫描设备查看 hashcat 后端信息。",
    deviceScanning: "正在扫描设备...",
    deviceScanDone: "设备扫描完成。",
    deviceScanFailed: "设备扫描失败。",
    deviceAuto: "自动",
    speed: "速度",
    temperature: "温度",
    utilization: "利用率",
    memory: "显存",
    performanceLowDesc: "轻量巡航",
    performanceDefaultDesc: "均衡调度",
    performanceHighDesc: "高速模式",
    performanceExtremeDesc: "满载冲刺",
    workloadLow: "1 低",
    workloadDefault: "2 默认",
    workloadHigh: "3 高",
    workloadExtreme: "4 极限",
    hashModePicker: "哈希类型",
    attackModePicker: "攻击类型",
    hashModeSearch: "搜索 md5、ntlm、1000、sha256...",
    noHashModes: "没有匹配的 Hash 类型",
    hashInput: "Hash 输入",
    hashInputHint: "粘贴文本或拖入 hash 文件",
    hashInputPlaceholder: "输入hash文本，每行一个hash",
    hashFileDrop: "拖动或选择hash文件",
    hashFileMode: "文件模式",
    hashTextMode: "文本模式",
    hashRecommendTitle: "Hash 类型推荐",
    hashRecommendHint: "根据样本格式推测，仅供参考。",
    hashRecommendEmpty: "粘贴 hash 后显示可能的 -m 模式。",
    hashOfficialIdentify: "官方识别",
    hashIdentifyRunning: "识别中",
    hashIdentifyEmpty: "hashcat 官方识别暂无结果。",
    applyRecommendation: "应用",
    confidenceHigh: "较高",
    confidenceMedium: "中等",
    confidenceLow: "较低",
    hashFile: "Hash 文件",
    notSelected: "未选择",
    dictionaryFile: "字典文件",
    rulesFile: "规则文件",
    useRules: "使用规则",
    add: "添加",
    noRules: "无规则",
    help: "帮助",
    file: "文件",
    maskPlaceholder: "?l?l?l?l?d?d",
    maskHelp: "?l 小写，?u 大写，?d 数字，?s 符号，?a 全集。普通字符会原样参与破解。",
    maskEstimate: "掩码预估",
    maskCandidates: "候选空间",
    maskEstimatedTime: "预计耗时",
    maskEstimateSpeed: "参考速度",
    maskEstimateUnknown: "等待运行速度",
    maskEstimateUnsupported: "包含自定义字符或未知 token，暂不能准确估算。",
    maskEstimatePartial: "该模式只估算掩码部分，字典行数未计入。",
    longTaskConfirm: "这个任务预计需要 {time}，候选空间 {candidates}。确认启动吗？",
    taskMayRunLong: "可能较久",
    incrementMask: "递增掩码",
    incrementRange: "长度范围",
    incrementMin: "最小",
    incrementMax: "最大",
    commandPreview: "命令预览",
    liveTerminal: "实时终端输出",
    expand: "展开",
    collapse: "收起",
    running: "运行中",
    waitingStart: "等待启动",
    waitingTask: "等待任务",
    crackFound: "发现破解结果",
    resultReport: "结果报告",
    passwordLabel: "密码",
    resultCount: "条",
    hashAlreadyCracked: "检测到已破解Hash！",
    resultEmptyForTask: "当前任务还没有写入 cracked.txt。",
    resultEmpty: "启动任务后，破解结果会显示在这里。",
    moreResults: "还有 {count} 条结果，可到历史页查看完整内容。",
    copyResults: "复制结果",
    openDir: "打开目录",
    resourcesTitle: "资源库",
    presets: "自定义预设",
    addPreset: "添加预设",
    addToGroup: "添加到分组",
    editPreset: "编辑预设",
    noPresets: "暂无预设。点击添加按钮创建攻击预设。",
    noDescription: "无描述",
    name: "名称",
    description: "描述",
    customCharset: "自定义字符集",
    browse: "浏览",
    clear: "清除",
    chooseFile: "选择文件",
    importDictionary: "导入字典",
    allTypes: "全部类型",
    resourceDictionary: "字典",
    resourceMask: "掩码",
    resourceRule: "规则",
    resourceCharset: "自定义字符",
    resourceTemplate: "候选模板",
    resourceSearch: "搜索 rockyou.txt、rules、masks...",
    customResources: "自定义资源",
    addCustomResource: "添加自定义资源",
    editCustomResource: "编辑自定义资源",
    dedupeDictionary: "去重",
    processing: "处理中...",
    saveCurrentMask: "保存当前掩码",
    saveCurrentTemplate: "保存当前模板",
    rule: "规则",
    enable: "启用",
    customName: "名称",
    customDescription: "说明",
    customMaskName: "自定义掩码",
    customTemplateName: "候选模板方案",
    customDictionaryName: "自定义字典",
    customCharsetName: "自定义字符",
    customRuleName: "自定义规则", 
    charsetSlot: "位置",
    charsetValue: "字符集内容",
    charsetHint: "mask 中可使用 ?1 ?2 ?3 ?4",
    manageCustomResources: "管理自定义资源",
    addMaskResource: "新增掩码",
    addTemplateResource: "新增模板",
    addCharsetResource: "新增字符集",
    importCustomDictionary: "导入字典副本",
    eachDictCreatePreset: "每个字典生成一个预设",
    selectedDictsCount: "已选择 {count} 个字典",
    eachDictWillGeneratePreset: "每个字典将生成一个预设",
    ruleEditor: "编辑器",
    caseConversion: "大小写转换",
    lowercaseAll: "小写所有字母",
    uppercaseAll: "大写所有字母",
    capitalizeFirst: "首字母大写其余小写",
    lowercaseFirst: "首字母小写其余大写",
    toggleCase: "反转大小写",
    toggleNthChar: "切换第N个字符大小写",
    characterChange: "字符变化",
    reverseString: "反转整个字符串",
    duplicateString: "重复字符串",
    repeatNtimes: "重复n次字符串",
    appendReverse: "末尾添加字符串的反转",
    moveFirstToEnd: "首部字符移动到末尾",
    moveLastToFirst: "末尾字符移动到首部",
    appendAfter: "后面添加",
    appendBefore: "前面添加",
    insertAtPosition: "在n位置插入字符",
    replaceAtPosition: "替换n位置字符",
    replaceChar: "替换所有字符a为b",
    repeatFirstChar: "重复第一个字符n次",
    repeatLastChar: "重复最后一个字符n次",
    position: "位置",
    originalChar: "原字符",
    replaceWith: "替换为",
    repeatEachChar: "重复每个字符",
    deleteFirstChar: "删除首字符",
    deleteLastChar: "删除尾字符",
    deleteCharAt: "删除位置n的字符",
    extractChars: "提取位置n开始的M个字符",
    deleteCharsFrom: "从位置n开始删除M个字符",
    deleteAllChar: "删除所有x字符",
    swapFirstTwo: "交换首部两个字符位置",
    swapLastTwo: "交换末尾两个字符位置",
    swapPositions: "交换位置N和M的字符",
    repeatStartN: "重复开始的N个字符",
    repeatEndN: "重复末尾的N个字符",
    positionN: "位置N",
    positionM: "位置M",
    advancedRules: "高级规则",
    ignoreLongerLength: "忽略长度大于N的密码",
    ignoreShorterLength: "忽略长度小于N的密码",
    onlyLengthEqual: "只使用长度等于N的密码",
    ignoreWithoutChar: "忽略不包含X的密码",
    ignoreNotStartWith: "忽略开头不是X的密码",
    ignoreNotEndWith: "忽略结尾不是X的密码",
    length: "长度",
    number: "数字",
    char: "字符",
    applyRule: "应用",
    previewRule: "预览规则",
    note: "说明",
    sameLineMutuallyExclusive: "同行两个选项互斥",
    eG: "例如",
    addRuleResource: "新增规则",
    importMaskFile: "导入掩码文件",
    importRuleFile: "导入规则文件",
    edit: "编辑",
    content: "内容",
    noCustomResources: "暂无自定义资源。点击管理按钮新增掩码、候选模板方案或导入字典。",
    delete: "删除",
    replace: "替换",
    reorder: "调序",
    builtinResources: "hashcat 自带资源",
    userDictionaries: "用户字典",
    useResource: "使用资源",
    usePreset: "使用预设",
    resourceRuleHelp: "规则文件：只用于字典攻击，会批量变形字典词，例如追加数字、大小写变化。",
    resourceMaskHelp: "掩码：用于掩码、字典+掩码、掩码+字典攻击。",
    resourceMaskFileHelp: "掩码文件：用于掩码攻击，里面保存常见 mask 模板。",
    resourceCharsetHelp: "字符集文件：给高级掩码使用，自定义 ?1/?2 这类字符范围。",
    resourceDictionaryHelp: "字典文件：用于字典、Hybrid 和候选模板攻击，作为中间词或基础词表。",
    resourceRecommendedBecause: "适合当前攻击模式",
    resourceNoRecommendations: "当前模式暂无特别推荐资源。",
    preview: "预览",
    resourcePreviewTitle: "资源预览",
    previewTruncated: "仅显示前 {count} 行，文件较大未完全加载。",
    previewEmpty: "文件为空或没有可显示内容。",
    copiedDictionaryOnly: "用户字典为只读预览；如需修改，请在自定义资源中导入字典副本。",
    readonlyFileWarning: "此文件无法编辑。只能修改软件数据目录中的文件。",
    largeDictionaryAppendOnly: "该字典较大，当前只载入预览内容。为避免误覆盖整本字典，本次只能追加新词条。",
    appendDictionaryLines: "追加词条",
    appendDictionaryPlaceholder: "每行一个新候选词，会追加到字典末尾。",
    use: "使用",
    noUserDictionaries: "暂无用户字典",
    noCustomMasks: "暂无自定义掩码预设",
    noRuleResources: "暂无规则资源",
    historyTitle: "历史任务",
    allStatus: "全部状态",
    statusCracked: "已破解",
    statusExhausted: "已耗尽",
    statusAborted: "已中止",
    statusFinished: "已完成",
    statusRunning: "运行中",
    statusError: "错误",
    statusStopped: "已暂停",
    manageQueue: "管理队列",
    finishManage: "完成管理",
    manageHistory: "管理历史",
    searchPlaceholder: "搜索任务名、标签...",
    load: "载入",
    rerun: "重跑",
    restore: "恢复",
    detail: "详情",
    noHistory: "暂无历史任务",
    copy: "复制",
    export: "导出",
    directory: "目录",
    noResults: "暂无结果",
    selectHistoryForResult: "选择一个历史任务查看结果",
    log: "日志",
    close: "关闭",
    logsTitle: "任务日志",
    selectTask: "选择任务",
    aiAnalyzing: "分析中",
    aiAnalyze: "AI 分析",
    noLogs: "暂无日志",
    selectTaskForLog: "选择一个任务查看日志",
    aiSettingsTitle: "AI 设置",
    language: "界面语言",
    chinese: "中文",
    english: "English",
    model: "模型",
    availableModels: "可用模型",
    chooseModel: "选择模型",
    connectionOk: "连接成功，获取到 {count} 个模型",
    testing: "测试中",
    testConnection: "测试连接",
    cancel: "取消",
    save: "保存",
    aiAnalysisTitle: "日志分析",
    helpAiAnalysisTitle: "帮助分析",
    noTaskSelected: "未选择任务",
    minimize: "最小化",
    aiConnecting: "正在连接 AI，分析内容会在这里实时出现...",
    noAiContent: "暂无分析内容",
    errorLabel: "错误",
    aiStreaming: "流式分析中，主界面可继续使用",
    aiFinished: "分析结束",
    terminalWaiting: "等待 hashcat 输出",
    stopRequested: "已请求检查点停止",
    resultsCopied: "结果已复制",
    resultsExported: "结果已导出",
    deleteConfirm: "删除该任务及本地结果文件？",
    taskFinished: "任务结束：{status}",
    sideRunningTitle: "努力计算中",
    sideIdleTitle: "正在休息中",
    sideRunningText: "别急，结果在路上",
    sideIdleText: "准备好开跑啦",
    hashSettings: "Hash 设置",
    selectHashMode: "选择哈希模式",
    restoreFailed: "恢复失败，已重新开始",
    builtinMaskName: "内置掩码",
    builtinDictionaryName: "内置字典",
    builtinRuleName: "内置规则",
    builtinEditableSuffix: " (可编辑)",
    missingHash: "请输入 Hash 值或选择 Hash 文件",
    missingHashMode: "请选择 Hash 模式",
    missingDictionary: "请选择字典文件",
    missingDictionary2: "请选择两个字典文件",
    missingMask: "请输入掩码或选择掩码文件",
    missingDictOrMask: "请选择字典和掩码",
    missingTemplate: "请输入前缀或后缀掩码",
    resourceInvalid: "已失效",
    Convert2hc22000Success: "WPA哈希文件转换成功",
    Convert2hc22000Cached: "使用缓存的转换文件",
    Convert2hc22000Failed: "WPA哈希文件转换失败，可能文件中未包含有效握手",
    optimizedKernel: "启用内核优化",
    skipDuplicateHashOnCrack: "破解成功后跳过相同哈希",
    resetToDefault: "恢复默认",
  },
  en: {
    appReady: "Ready",
    appMissing: "Missing",
    taskHealth: "Task",
    taskBusy: "Working",
    taskIdle: "Idle",
    settingsTitle: "Settings",
    helpTitle: "Help",
    aboutTitle: "About",
    advancedSettings: "Advanced",
    helpSubtitle: "Attack guides and AI advisor",
    attackTutorials: "Attack Quick Guide",
    aiHashAdvisor: "Ask AI",
    helpDictionaryTitle: "Dictionary Attack -a 0 / -a 1",
    helpDictionaryBody: "Tries candidates from a wordlist. Useful when passwords may come from common words, leaks, names, phone fragments, or targeted lists. Rule files can mutate words in bulk.",
    helpMaskTitle: "Mask Attack -a 3",
    helpMaskBody: "Enumerates a fixed pattern with charsets like ?d, ?l, ?u, ?s. Example: 2015?d?d?d?d tries 20150000 through 20159999.",
    helpHybridTitle: "Hybrid Attack -a 6 / -a 7",
    helpHybridBody: "-a 6 is wordlist + mask, such as admin?d?d. -a 7 is mask + wordlist, such as ?d?dadmin.",
    helpTemplateTitle: "Template Candidates",
    helpTemplateBody: "For patterns like ?d?d + dictionary word + ?d?d. The app generates a temporary candidate dictionary, then runs hashcat with -a 0.",
    helpRuleTitle: "Rule Attack",
    helpRuleBody: "Rules work with dictionary attacks and mutate words automatically, such as capitalization, appending digits, or character replacement.",
    aiQuestion: "Question",
    aiQuestionPlaceholder: "Example: What hash type does this look like? Is my mask reasonable? What should I try next?",
    useCurrentConfig: "Current task config included",
    chooseHashTxt: "Choose hash.txt",
    askAi: "Ask AI",
    aiThinking: "AI thinking",
    aiAnswer: "AI Answer",
    aiStartedInWindow: "AI analysis is running in a separate window. You can minimize it or keep using the main UI.",
    applyAiSuggestion: "Apply to Task",
    noAiSuggestion: "No applicable task config was found in the AI result.",
    aiSuggestionApplied: "Task config filled from AI suggestion.",
    refresh: "Refresh",
    hashcatUpdate: "Hashcat Update",
    hashcatUpdateHint: "Check GitHub releases, install to resources/hashcat-current in the tool folder, and keep the embedded hashcat as fallback.",
    checkUpdate: "Check Update",
    installUpdate: "Update hashcat",
    updateCurrent: "Current",
    updateLatest: "Latest",
    updatePackage: "Package",
    updateUpToDate: "Already latest",
    updateAvailable: "Update available",
    updateNotChecked: "Not checked",
    updateRunning: "Updating",
    updateLog: "Update Log",
    openRelease: "Open Release",
    tabConfig: "Task",
    tabResources: "Resources",
    tabHistory: "History",
    tabLogs: "Logs",
    attackConfigTitle: "Task Config",
    attackSettings: "Attack Settings",
    addToSequence: "Add to Sequence",
    attackSequence: "Attack Sequence",
    dictionary: "Dictionary",
    dictionaryCombo: "Dictionary Combo",
    leftRule: "Left Rule",
    rightRule: "Right Rule",
    rulePlaceholder: "Enter rule string, e.g.: $0$1$2",
    mask: "Mask",
    hybridDictMask: "Dict+Mask",
    hybridMaskDict: "Mask+Dict",
    templateAttack: "Template",
    prefixMask: "Prefix Mask",
    suffixMask: "Suffix Mask",
    templateHint: "Generate prefix mask + dictionary word + suffix mask, then crack with -a 0.",
    templatePreviewWord: "word",
    start: "Start",
    stop: "Stop",
    attackControl: "Attack Control",
    taskName: "Task Name",
    taskNamePlaceholder: "Optional, useful in history",
    hashMode: "Hash Mode",
    hashModePlaceholder: "e.g. 0 / 1000 / 1400",
    workload: "Workload",
    performanceMode: "Performance Mode",
    deviceControl: "Device Performance",
    deviceControlHint: "Choose CPU/GPU, pin device IDs, and watch speed, temperature, utilization, and VRAM.",
    scanDevices: "Scan Devices",
    deviceTypes: "Device Types",
    cpuDevice: "CPU",
    gpuDevice: "GPU",
    deviceIds: "Device IDs",
    deviceIdsPlaceholder: "e.g. 1 or 1,2. Leave empty for hashcat auto selection",
    noDeviceStatus: "Live device status appears\n after a task starts.",
    backendDeviceInfo: "Backend Device Info",
    backendRawSummary: "Raw Summary",
    deviceIdLabel: "Device ID",
    deviceMemory: "Memory",
    deviceBackend: "Backend",
    deviceVendor: "Vendor",
    deviceProcessor: "Processor",
    deviceScanReady: "Click Scan Devices to inspect hashcat backend info.",
    deviceScanning: "Scanning devices...",
    deviceScanDone: "Device scan complete.",
    deviceScanFailed: "Device scan failed.",
    deviceAuto: "Auto",
    speed: "Speed",
    temperature: "Temp",
    utilization: "Utilization",
    memory: "VRAM",
    performanceLowDesc: "Light cruise",
    performanceDefaultDesc: "Balanced",
    performanceHighDesc: "High speed",
    performanceExtremeDesc: "Full sprint",
    workloadLow: "1 Low",
    workloadDefault: "2 Default",
    workloadHigh: "3 High",
    workloadExtreme: "4 Extreme",
    hashModePicker: "Hash Type",
    attackModePicker: "Attack Type",
    hashModeSearch: "Search md5, ntlm, 1000, sha256...",
    noHashModes: "No matching hash types",
    hashInput: "Hash Input",
    hashInputHint: "Paste text or drop a hash file",
    hashInputPlaceholder: "Enter hash text, one hash per line",
    hashFileDrop: "Drag or select hash file",
    hashFileMode: "File Mode",
    hashTextMode: "Text Mode",
    hashRecommendTitle: "Hash Type Suggestions",
    hashRecommendHint: "Guessed from sample format only.",
    hashRecommendEmpty: "Paste a hash to see possible -m modes.",
    hashOfficialIdentify: "Official Identify",
    hashIdentifyRunning: "Identifying",
    hashIdentifyEmpty: "No official hashcat identify result.",
    applyRecommendation: "Apply",
    confidenceHigh: "High",
    confidenceMedium: "Medium",
    confidenceLow: "Low",
    hashFile: "Hash File",
    notSelected: "Not selected",
    dictionaryFile: "Dictionary File",
    rulesFile: "Rule Files",
    useRules: "Use Rules",
    add: "Add",
    noRules: "No rules",
    help: "Help",
    file: "File",
    maskPlaceholder: "?l?l?l?l?d?d",
    maskHelp: "?l lowercase, ?u uppercase, ?d digit, ?s symbol, ?a all printable. Literal characters are used as-is.",
    maskEstimate: "Mask Estimate",
    maskCandidates: "Candidates",
    maskEstimatedTime: "Estimated Time",
    maskEstimateSpeed: "Reference Speed",
    maskEstimateUnknown: "Waiting for runtime speed",
    maskEstimateUnsupported: "Contains custom charsets or unknown tokens, so it cannot be estimated accurately yet.",
    maskEstimatePartial: "This mode estimates the mask portion only; dictionary line count is not included.",
    longTaskConfirm: "This task is estimated to take {time} with {candidates} candidates. Start anyway?",
    taskMayRunLong: "May run long",
    incrementMask: "Increment Mask",
    incrementRange: "Length Range",
    incrementMin: "Min",
    incrementMax: "Max",
    commandPreview: "Command Preview",
    liveTerminal: "Live Terminal Output",
    expand: "Expand",
    collapse: "Collapse",
    running: "Running",
    waitingStart: "Waiting to start",
    waitingTask: "Waiting for task",
    crackFound: "Cracked Result Found",
    resultReport: "Result Report",
    hashAlreadyCracked: "A cracked hash has been detected!",
    passwordLabel: "Password",
    resultCount: "results",
    resultEmptyForTask: "This task has not written cracked.txt yet.",
    resultEmpty: "Results will appear here after a task starts.",
    moreResults: "{count} more results. Open History to view all.",
    copyResults: "Copy Results",
    openDir: "Open Folder",
    resourcesTitle: "Resource Library",
    presets: "Custom Presets",
    addPreset: "Add Preset",
    addToGroup: "Add to Group",
    editPreset: "Edit Preset",
    noPresets: "No presets yet. Click Add to create an attack preset.",
    noDescription: "No description",
    customCharset: "Custom Charset",
    browse: "Browse",
    clear: "Clear",
    chooseFile: "Choose File",
    name: "name",
    description: "description",
    importDictionary: "Import Dictionary",
    allTypes: "All Types",
    resourceDictionary: "Dictionary",
    resourceMask: "Mask",
    resourceRule: "Rule",
    resourceCharset: "Charset",
    resourceTemplate: "Template",
    resourceSearch: "Search rockyou.txt, rules, masks...",
    customResources: "Custom Resources",
    addCustomResource: "Add Custom Resource",
    editCustomResource: "Edit Custom Resource",
    dedupeDictionary: "Deduplicate",
    processing: "Processing...",
    saveCurrentMask: "Save Current Mask",
    saveCurrentTemplate: "Save Current Template",
    rule: "rule",
    enable: "enable",
    customName: "Name",
    customDescription: "Description",
    customMaskName: "Custom Mask",
    customTemplateName: "Template Candidate Plan",
    customDictionaryName: "Custom Dictionary",
    customCharsetName: "Custom Charset",
    customRuleName: "Custom Rule",
    charsetSlot: "Slot",
    charsetValue: "Charset",
    charsetHint: "Use ?1 ?2 ?3 ?4 in masks",
    manageCustomResources: "Manage Custom Resources",
    addMaskResource: "Add Mask",
    addTemplateResource: "Add Template",
    addCharsetResource: "Add Charset",
    importCustomDictionary: "Import Dictionary Copy",
    eachDictCreatePreset: "Create preset for each dictionary",
    selectedDictsCount: "{count} dictionaries selected",
    eachDictWillGeneratePreset: "Each dictionary will generate a preset",
    ruleEditor: "Editor",
    caseConversion: "Case Conversion",
    lowercaseAll: "Lowercase All",
    uppercaseAll: "Uppercase All",
    capitalizeFirst: "Capitalize First",
    lowercaseFirst: "Lowercase First",
    toggleCase: "Toggle Case",
    toggleNthChar: "Toggle Nth Character",
    characterChange: "Character Change",
    reverseString: "Reverse String",
    duplicateString: "Duplicate String",
    repeatNtimes: "Repeat N Times",
    appendReverse: "Append Reverse",
    moveFirstToEnd: "Move First to End",
    moveLastToFirst: "Move Last to First",
    appendAfter: "Append After",
    appendBefore: "Append Before",
    insertAtPosition: "Insert at Position",
    replaceAtPosition: "Replace at Position",
    replaceChar: "Replace Character",
    repeatFirstChar: "Repeat First Char",
    repeatLastChar: "Repeat Last Char",
    position: "position",
    originalChar: "original",
    replaceWith: "replace with",
    repeatEachChar: "Repeat Each Char",
    deleteFirstChar: "Delete First Char",
    deleteLastChar: "Delete Last Char",
    deleteCharAt: "Delete Char at Position",
    extractChars: "Extract M Chars from N",
    deleteCharsFrom: "Delete M Chars from N",
    deleteAllChar: "Delete All X Chars",
    swapFirstTwo: "Swap First Two Chars",
    swapLastTwo: "Swap Last Two Chars",
    swapPositions: "Swap Nth and Mth Char",
    repeatStartN: "Repeat First N Chars",
    repeatEndN: "Repeat Last N Chars",
    positionN: "pos N",
    positionM: "pos M",
    advancedRules: "Advanced Rules",
    ignoreLongerLength: "Ignore Longer Than N",
    ignoreShorterLength: "Ignore Shorter Than N",
    onlyLengthEqual: "Only Length Equal N",
    ignoreWithoutChar: "Ignore Without X",
    ignoreNotStartWith: "Ignore Not Starting With X",
    ignoreNotEndWith: "Ignore Not Ending With X",
    length: "length",
    number: "number",
    char: "char",
    applyRule: "Apply",
    previewRule: "Preview Rule",
    note: "Note",
    sameLineMutuallyExclusive: "Options on the same line are mutually exclusive",
    eG: "e.g.",
    addRuleResource: "Add Rule",
    importMaskFile: "Import Mask File",
    importRuleFile: "Import Rule File",
    edit: "Edit",
    content: "Content",
    noCustomResources: "No custom resources yet. Open the manager to add masks, template plans, or dictionaries.",
    delete: "Delete",
    replace: "Replace",
    reorder: "Reorder",
    builtinResources: "Built-in Resources",
    userDictionaries: "User Dictionaries",
    useResource: "Use Resource",
    usePreset: "Use Preset",
    resourceRuleHelp: "Rule file: dictionary attack only. Mutates words, such as appending digits or changing case.",
    resourceMaskHelp: "Mask: used for masking, dictionary + masking, masking + dictionary attacks.",
    resourceMaskFileHelp: "Mask file: used by mask attack. Stores common mask templates.",
    resourceCharsetHelp: "Charset file: advanced mask usage for custom ?1/?2 character ranges.",
    resourceDictionaryHelp: "Dictionary file: used by dictionary, Hybrid, and template attacks as base words.",
    resourceRecommendedBecause: "Recommended for current mode",
    resourceNoRecommendations: "No specific recommendations for this mode.",
    preview: "Preview",
    resourcePreviewTitle: "Resource Preview",
    previewTruncated: "Showing the first {count} lines only. The file was not fully loaded.",
    previewEmpty: "The file is empty or has no displayable content.",
    copiedDictionaryOnly: "User dictionaries are read-only here. Import a dictionary copy in Custom Resources to edit it.",
    readonlyFileWarning: "This file cannot be edited. Only files imported into the application data directory can be modified.",
    largeDictionaryAppendOnly: "This dictionary is large, so only a preview was loaded. To avoid overwriting the full file, this edit can only append new lines.",
    appendDictionaryLines: "Append Lines",
    appendDictionaryPlaceholder: "One candidate per line. New lines will be appended to the dictionary.",
    use: "Use",
    noUserDictionaries: "No user dictionaries",
    noCustomMasks: "No custom mask presets",
    noRuleResources: "No rule resources",
    historyTitle: "Task History",
    allStatus: "All Status",
    statusCracked: "Cracked",
    statusExhausted: "Exhausted",
    statusAborted: "Aborted",
    statusFinished: "Finished",
    statusRunning: "Running",
    statusError: "Error",
    statusStopped: "Stopped",
    manageQueue: "Manage Queue",
    finishManage: "Finish Manage",
    manageHistory: "Manage History",
    searchPlaceholder: "Search task name, tags...",
    load: "Load",
    rerun: "Rerun",
    restore: "Restore",
    detail: "Detail",
    noHistory: "No task history",
    copy: "Copy",
    export: "Export",
    directory: "Folder",
    noResults: "No results",
    selectHistoryForResult: "Select a history task to view results",
    log: "Log",
    close: "Close",
    logsTitle: "Task Logs",
    selectTask: "Select task",
    aiAnalyzing: "Analyzing",
    aiAnalyze: "AI Analyze",
    noLogs: "No logs",
    selectTaskForLog: "Select a task to view logs",
    aiSettingsTitle: "AI Settings",
    language: "Interface Language",
    chinese: "中文",
    english: "English",
    model: "Model",
    availableModels: "Available Models",
    chooseModel: "Choose model",
    connectionOk: "Connected. Found {count} models",
    testing: "Testing",
    testConnection: "Test Connection",
    cancel: "Cancel",
    save: "Save",
    aiAnalysisTitle: "Log Analysis",
    helpAiAnalysisTitle: "Help Analysis",
    noTaskSelected: "No task selected",
    minimize: "Minimize",
    aiConnecting: "Connecting to AI. Analysis will stream here...",
    noAiContent: "No analysis yet",
    errorLabel: "Error",
    aiStreaming: "Streaming analysis. You can keep using the main window",
    aiFinished: "Analysis finished",
    terminalWaiting: "Waiting for hashcat output",
    stopRequested: "Checkpoint stop requested",
    resultsCopied: "Results copied",
    resultsExported: "Results exported",
    deleteConfirm: "Delete this task and local result files?",
    taskFinished: "Task finished: {status}",
    sideRunningTitle: "Calculating",
    sideIdleTitle: "Resting",
    sideRunningText: "Results are on the way",
    sideIdleText: "Ready when you are",
    hashSettings: "Hash Settings",
    selectHashMode: "Select Hash Mode",
    restoreFailed: "Restore failed, restarting from beginning",
    builtinMaskName: "Built-in Mask",
    builtinDictionaryName: "Built-in Dictionary",
    builtinRuleName: "Built-in Rule",
    builtinEditableSuffix: " (Editable)",
    missingHash: "Please enter Hash or select Hash file",
    missingHashMode: "Please select Hash mode",
    missingDictionary: "Please select dictionary file",
    missingDictionary2: "Please select two dictionary files",
    missingMask: "Please enter mask or select mask file",
    missingDictOrMask: "Please select dictionary and mask",
    missingTemplate: "Please enter prefix or suffix mask",
    resourceInvalid: "Invalid",
    Convert2hc22000Success: "WPA hash file converted successfully",
    Convert2hc22000Cached: "Using cached converted file",
    Convert2hc22000Failed: "WPA hash file conversion failed, the file may not contain a valid handshake",
    optimizedKernel: "Enable Optimized Kernel",
    skipDuplicateHashOnCrack: "Skip duplicate hash tasks on crack success",
    resetToDefault: "Reset to Default",
  },
} as const;

type UiText = Record<keyof typeof UI_TEXT.zh, string>;

const ZH_TEXT: UiText = {
  ...UI_TEXT.en,
  ...ZH_TEXT_OVERRIDES,
};

const STATUS_TEXT: Record<Language, Record<string, string>> = {
  zh: {
    cracked: "已破解",
    exhausted: "已耗尽",
    aborted: "已中止",
    checkpoint: "检查点中止",
    finished: "已完成",
    running: "运行中",
    error: "错误",
    "backend-error": "错误",
  },
  en: {
    cracked: "Cracked",
    exhausted: "Exhausted",
    aborted: "Aborted",
    checkpoint: "Checkpoint",
    finished: "Finished",
    running: "Running",
    error: "Error",
    "backend-error": "Backend Error",
  },
};

function getInitialLanguage(): Language {
  const saved = localStorage.getItem(LANGUAGE_STORAGE_KEY);
  return saved === "en" || saved === "zh" ? saved : "zh";
}

// 从结果内容中提取密码
function extractPasswordsFromResults(content: string): string[] {
  const passwords: string[] = [];
  const lines = content.split(/\r?\n/);
  
  for (const line of lines) {
    const trimmedLine = line.trim();
    if (!trimmedLine) continue;
    
    // 找到最后一个冒号的位置
    const lastColonIndex = trimmedLine.lastIndexOf(':');
    if (lastColonIndex === -1 || lastColonIndex === trimmedLine.length - 1) {
      continue;
    }
    
    // 提取最后一个冒号后的内容
    let password = trimmedLine.substring(lastColonIndex + 1);
    
    // 处理 $HEX[xxxx] 格式
    const hexMatch = password.match(/^\$HEX$$([0-9a-fA-F]+)$$$/);
    if (hexMatch) {
      try {
        password = hexToString(hexMatch[1]);
      } catch {
        // 转换失败则保留原始字符串
      }
    }
    
    if (password) {
      passwords.push(password);
    }
  }
  
  return passwords;
}

// 十六进制字符串转普通字符串（支持中文）
function hexToString(hex: string): string {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex string");
  }
  
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substring(i, i + 2), 16));
  }
  
  return new TextDecoder('utf-8').decode(new Uint8Array(bytes));
}

// 保存/加载提取的密码
const EXTRACTED_PASSWORDS_STORAGE_KEY = "hashcatgui-extracted-passwords";

function saveExtractedPasswords(taskId: string, passwords: string[]) {
  try {
    const saved: Record<string, { passwords: string[]; extractedAt: string }> = JSON.parse(
      localStorage.getItem(EXTRACTED_PASSWORDS_STORAGE_KEY) || "{}"
    );
    saved[taskId] = { passwords, extractedAt: new Date().toISOString() };
    localStorage.setItem(EXTRACTED_PASSWORDS_STORAGE_KEY, JSON.stringify(saved));
  } catch (e) {
    console.error("Failed to save passwords:", e);
  }
}

function loadExtractedPasswords(taskId: string): string[] | null {
  try {
    const saved = JSON.parse(localStorage.getItem(EXTRACTED_PASSWORDS_STORAGE_KEY) || "{}");
    return saved[taskId]?.passwords || null;
  } catch (e) {
    return null;
  }
}

function deleteExtractedPasswords(taskId: string) {
  try {
    const saved: Record<string, { passwords: string[]; extractedAt: string }> = JSON.parse(
      localStorage.getItem(EXTRACTED_PASSWORDS_STORAGE_KEY) || "{}"
    );
    delete saved[taskId];
    localStorage.setItem(EXTRACTED_PASSWORDS_STORAGE_KEY, JSON.stringify(saved));
  } catch (e) {
    console.error("Failed to delete extracted passwords:", e);
  }
}

export default function App() {
  const [language, setLanguage] = useState<Language>(() => getInitialLanguage());
  const [updateStatus, setUpdateStatus] = useState<"idle" | "checking" | "latest" | "available">("idle");
  const [latestVersion, setLatestVersion] = useState<string>("");
  const [showUpdateDialog, setShowUpdateDialog] = useState(false);
  const [updateResult, setUpdateResult] = useState<{ hasUpdate: boolean; latest: string } | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>("config");
  const [info, setInfo] = useState<HashcatInfo | null>(null);
  const [hashModes, setHashModes] = useState<HashModeInfo[]>([]);
  const [resources, setResources] = useState<ResourceInfo[]>([]);
  const [userDictionaries, setUserDictionaries] = useState<UserDictionary[]>([]);
  
  const [_ruleEditorOpen, setRuleEditorOpen] = useState(false);
  const [ruleEditorTarget, setRuleEditorTarget] = useState<"left" | "right">("left");

  useCallback((target: "left" | "right") => {
    setRuleEditorTarget(target);
    setRuleEditorOpen(true);
  }, []);

  // 所有数据初始化为空数组，从后端加载
  const [customResources, setCustomResources] = useState<CustomResource[]>([]);
  const [groups, setGroups] = useState<{ id: string; name: string; resourceIds: string[]; expanded: boolean }[]>([]);
  const [manageResources, setManageResources] = useState<(CustomResource & { source: "custom" | "user" })[]>([]);
  const [presets, setPresets] = useState<PresetConfig[]>([]);
  const [presetGroups, setPresetGroups] = useState<PresetGroup[]>([]);

  // 添加从后端加载数据的函数
  useEffect(() => {
    loadAllDataFromBackend();

    // 设置窗口标题，包含版本号
    const name = pkg.name;
    const version = pkg.version;
    const author = pkg.author;
    const window = getCurrentWindow();
    window.setTitle(`${name} v${version} (by ${author})`);
  }, []);

  // 检测更新
  useEffect(() => {
    const checkForUpdates = async () => {
      try {
        const latest = await invoke<string>("check_update");
        const currentVersion = pkg.version;
        if (latest && latest !== currentVersion) {
          setLatestVersion(latest);
          setUpdateStatus("available");
          setUpdateResult({ hasUpdate: true, latest });
          setShowUpdateDialog(true);
        } else if (latest === currentVersion) {
          setLatestVersion(latest);
          setUpdateStatus("latest");
        }
      } catch (e) {
        console.error("检查更新失败 / Failed to check for updates:", e);
      }
    };

    checkForUpdates();
  }, [language]);

  useEffect(() => {
    const combined: (CustomResource & { source: "custom" | "user" })[] = [
      ...customResources
        .map(r => ({ ...r, source: "custom" as const }))
        .sort((a, b) => (a.sortOrder || 0) - (b.sortOrder || 0)),
      ...userDictionaries.map(dict => ({
        id: `userdict-${dict.path}`,
        type: "dictionary" as const,
        name: dict.name,
        description: "",
        path: dict.path,
        size: dict.size,
        createdAt: new Date().toISOString(),
        source: "user" as const
      }))
    ];
    setManageResources(combined);
  }, [customResources, userDictionaries]);

  const loadAllDataFromBackend = async () => {
    try {
      // 加载预设
      const presetsData = await invoke<string>("read_presets_file");
      if (presetsData) {
        const parsedPresets = JSON.parse(presetsData);
        // 检查预设文件的有效性 ← 添加这部分代码
        const checkedPresets = await Promise.all(
          parsedPresets.map(async (preset: PresetConfig) => ({
            ...preset,
            isValid: await checkPresetFiles(preset),
          }))
        );
        setPresets(checkedPresets);  // 使用检查后的预设
      }
      
      // 加载预设分组
      const presetGroupsData = await invoke<string>("read_preset_groups_file");
      if (presetGroupsData) {
        setPresetGroups(JSON.parse(presetGroupsData));
      }
      
      // 加载自定义资源
      const customResourcesData = await invoke<string>("read_custom_resources_file");
      if (customResourcesData) {
        const parsed = JSON.parse(customResourcesData);
        setCustomResources(parsed);
      }
      
      // 加载资源分组
      const groupsData = await invoke<string>("read_resource_groups_file");
      if (groupsData) {
        setGroups(JSON.parse(groupsData));
      }

      await refreshResources();
    } catch (error) {
      console.error("Failed to load data from backend:", error);
    }
  };


  // 清空攻击配置（通用函数）
  const clearAttackConfig = () => {
    setAttackMode(0);           // 重置攻击模式为字典攻击
    setDictionaryPath("");      // 清空字典路径
    setDictionaryPath2("");     // 清空第二个字典路径
    setDictionaryPaths([]);
    setMask("");                // 清空掩码
    setMaskFile("");            // 清空掩码文件路径
    setTemplatePrefixMask("");  // 清空模板前缀掩码
    setTemplateSuffixMask("");  // 清空模板后缀掩码
    setIncrement(false);        // 关闭增量模式
    setIncrementMin("");         // 重置增量最小值
    setIncrementMax("");         // 重置增量最大值
    setCustomCharset1("");      // 清空自定义字符集1
    setCustomCharset2("");      // 清空自定义字符集2
    setCustomCharset3("");      // 清空自定义字符集3
    setCustomCharset4("");      // 清空自定义字符集4
    setRulePaths([]);           // 清空规则文件路径
    setLeftRule("");            // 清空左规则
    setRightRule("");           // 清空右规则
    setCharsetFile1("");        // 清空字符集文件1
    setCharsetFile2("");        // 清空字符集文件2
    setCharsetFile3("");        // 清空字符集文件3
    setCharsetFile4("");        // 清空字符集文件4
    setUseRules(false);
    setUseLeftRule(false);
    setUseRightRule(false);
  };

  const resetToDefault = () => {
    // 清空任务表单
    clearTaskForm();
    // 重置高级设置到默认值
    setOptimizedKernel(true);
    setSkipDuplicateHashOnCrack(true);
    setWorkloadProfile(3);
    setDeviceTypes(["2"]);
    setDeviceIds("");
    // 清空攻击序列
    clearAttackSequence();
  };

  // 使用预设函数
  const usePreset = async (preset: PresetConfig) => {

    // 收集预设引用的所有文件路径（不包括 leftRule 和 rightRule，它们是字符串规则）
    const filePathSet = new Set<string>();
    if (preset.dictionaryPath) filePathSet.add(preset.dictionaryPath);
    if (preset.dictionaryPath2) filePathSet.add(preset.dictionaryPath2);
    if (preset.dictionaryPaths) preset.dictionaryPaths.forEach(p => filePathSet.add(p));
    if (preset.maskPath) filePathSet.add(preset.maskPath);
    if (preset.rulePaths) preset.rulePaths.forEach(p => filePathSet.add(p));
    
    // 检查文件是否存在
    const missingFiles = await Promise.all(
      Array.from(filePathSet).map(async path => ({ path, exists: await invoke('check_file_exists', { path }) }))
    ).then(results => results.filter(r => !r.exists).map(r => r.path));
    
    // 如果有文件不存在，显示错误提示并返回
    if (missingFiles.length > 0) {
      const errorMsg = language === "zh"
        ? `预设引用的文件不存在，无法使用：\n${missingFiles.join('\n')}`
        : `The preset references missing files, cannot apply:\n${missingFiles.join('\n')}`;
      setError(errorMsg);
      return;
    }

    clearAttackConfig();
    setAttackMode(preset.attackMode);
    
    if (preset.hashMode) setHashMode(preset.hashMode);
    if (preset.dictionaryPaths) setDictionaryPaths(preset.dictionaryPaths);
    if (preset.dictionaryPath) setDictionaryPath(preset.dictionaryPath);
    if (preset.dictionaryPath2) setDictionaryPath2(preset.dictionaryPath2);
    if (preset.mask) setMask(preset.mask);
    if (preset.maskPath) setMaskFile(preset.maskPath);
    if (preset.prefixMask) setTemplatePrefixMask(preset.prefixMask);
    if (preset.suffixMask) setTemplateSuffixMask(preset.suffixMask);
    if (preset.useLeftRule !== undefined) setUseLeftRule(preset.useLeftRule);
    if (preset.leftRule) setLeftRule(preset.leftRule);
    if (preset.useRightRule !== undefined) setUseRightRule(preset.useRightRule);
    if (preset.rightRule) setRightRule(preset.rightRule);
    if (preset.customCharsets) {
      setCharsetEnabled(true);
      Object.entries(preset.customCharsets).forEach(([slot, value]) => {
        const slotNum = Number(slot) as 1 | 2 | 3 | 4;
        if (slotNum >= 1 && slotNum <= 4) {
          [setCustomCharset1, setCustomCharset2, setCustomCharset3, setCustomCharset4][slotNum - 1](value);
        }
      });
    }
    if (preset.rulePaths && preset.rulePaths.length > 0) {
      setUseRules(true);
      setRulePaths(preset.rulePaths);
    }
    if (preset.increment !== undefined) setIncrement(preset.increment);
    if (preset.incrementMin) setIncrementMin(preset.incrementMin);
    if (preset.incrementMax) setIncrementMax(preset.incrementMax);
    if (preset.useRules !== undefined) setUseRules(preset.useRules);
    if (preset.useLeftRule !== undefined) setUseLeftRule(preset.useLeftRule);  // 新增
    if (preset.useRightRule !== undefined) setUseRightRule(preset.useRightRule); // 新增
  };

  
  const [queueItems, setQueueItems] = useState<QueueItem[]>(() => loadQueueItems());
  
  useEffect(() => {
    void (async () => {
      // 找出所有没有 hashContent 的待执行任务
      const itemsWithoutHash = queueItems.filter(item => !item.hashContent && (item.status === "pending" || item.status === "stopped"));
      
      if (itemsWithoutHash.length === 0) return;
      
      // 批量读取并更新
      const updates: { id: string; hashContent: string }[] = [];
      for (const item of itemsWithoutHash) {
        let content = "";
        if (item.config.hashText?.trim()) {
          content = normalizeHashContent(item.config.hashText);
        } else if (item.config.hashFile) {
          try {
            const response = await invoke<FilePreviewResponse>("preview_text_file", {
              path: item.config.hashFile,
              allowFull: true
            });
            content = normalizeHashContent(response.content);
          } catch {
            content = item.config.hashFile;
          }
        }
        updates.push({ id: item.id, hashContent: content });
      }
      
      // 更新队列状态
      setQueueItems((current) => 
        current.map(item => {
          const update = updates.find(u => u.id === item.id);
          return update ? { ...item, hashContent: update.hashContent } : item;
        })
      );
    })();
  }, []);

  const [queuePaused, setQueuePaused] = useState(true);
  const [tasks, setTasks] = useState<TaskManifest[]>([]);
  const [selectedTaskId, setSelectedTaskId] = useState("");
  const [taskId, setTaskId] = useState("");
  const [historyStatusFilter, setHistoryStatusFilter] = useState("");
  const [historySearchQuery, setHistorySearchQuery] = useState("");
  const [running, setRunning] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [logs, setLogs] = useState<LogPayload[]>([]);
  const [taskLog, setTaskLog] = useState<ResultsResponse | null>(null);
  const [taskLogTaskId, setTaskLogTaskId] = useState("");
  const [results, setResults] = useState<ResultsResponse | null>(null);
  const [resultsTaskId, setResultsTaskId] = useState("");
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);
  const [guideDismissed, setGuideDismissed] = useState(() => localStorage.getItem(FIRST_GUIDE_STORAGE_KEY) === "1");
  const [updateOpen, setUpdateOpen] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [savedOptimizedKernel, setSavedOptimizedKernel] = useState(true);
  const [savedSkipDuplicateHashOnCrack, setSavedSkipDuplicateHashOnCrack] = useState(true);
  const [queueTerminalExpanded, setQueueTerminalExpanded] = useState(false);
  const [savedDeviceIds, setSavedDeviceIds] = useState("");
  const [savedDeviceTypes, setSavedDeviceTypes] = useState<string[]>([]);
  const [savedWorkloadProfile, setSavedWorkloadProfile] = useState(3);
  const [updateInfo, setUpdateInfo] = useState<HashcatUpdateInfo | null>(null);
  const [updateLogs, setUpdateLogs] = useState<HashcatUpdateEvent[]>([]);
  const [updateRunning, setUpdateRunning] = useState(false);
  const [hashcatPathStatus, setHashcatPathStatus] = useState<HashcatPathStatus | null>(null);

  const [simpleMode, setSimpleMode] = useState<boolean>(() => {
    const saved = localStorage.getItem(SIMPLE_MODE_STORAGE_KEY);
    return saved === "true";
  });
  useEffect(() => {
    localStorage.setItem(SIMPLE_MODE_STORAGE_KEY, simpleMode.toString());
  }, [simpleMode]);

  
  const [taskName, setTaskName] = useState("");
  const [hashMode, setHashMode] = useState("0");
  const [modeQuery, setModeQuery] = useState("");
  const [attackMode, setAttackMode] = useState<AttackMode>(0);
  const [hashText, setHashText] = useState("");
  const [hashFile, setHashFile] = useState("");
  const [originalHashFile, setOriginalHashFile] = useState("");
  const [hc22000Info, setHc22000Info] = useState<Hc22000Info | null>(null);
  const [selectedHc22000Indices, setSelectedHc22000Indices] = useState<number[]>([]); // 选中的行索引
  const [hc22000SelectionMode, setHc22000SelectionMode] = useState<'multi' | 'single'>('multi'); // 多选/单选模式
  const [dictionaryPath, setDictionaryPath] = useState("");
  const [dictionaryPath2, setDictionaryPath2] = useState("");
  const [dictionaryPaths, setDictionaryPaths] = useState<string[]>([]);
  const [mask, setMask] = useState("");
  const [maskFile, setMaskFile] = useState("");
  const [templatePrefixMask, setTemplatePrefixMask] = useState("");
  const [templateSuffixMask, setTemplateSuffixMask] = useState("");
  const [increment, setIncrement] = useState(false);
  const [incrementMin, setIncrementMin] = useState("");
  const [incrementMax, setIncrementMax] = useState("");
  const [customCharset1, setCustomCharset1] = useState("");
  const [customCharset2, setCustomCharset2] = useState("");
  const [customCharset3, setCustomCharset3] = useState("");
  const [customCharset4, setCustomCharset4] = useState("");
  const [charsetFile1, setCharsetFile1] = useState("");
  const [charsetFile2, setCharsetFile2] = useState("");
  const [charsetFile3, setCharsetFile3] = useState("");
  const [charsetFile4, setCharsetFile4] = useState("");
  const [charsetEnabled, setCharsetEnabled] = useState(false);
  const [rulePaths, setRulePaths] = useState<string[]>([]);
  const [leftRule, setLeftRule] = useState("");
  const [rightRule, setRightRule] = useState("");
  const [selectedResourceTarget, setSelectedResourceTarget] = useState<"primary" | "secondary">("primary");
  const [useRules, setUseRules] = useState(false);
  const [useLeftRule, setUseLeftRule] = useState(false);
  const [useRightRule, setUseRightRule] = useState(false);

  const loadAdvancedSettings = (): { optimizedKernel: boolean; skipDuplicateHashOnCrack: boolean; workloadProfile: number; deviceTypes: string[]; deviceIds: string } => {
    try {
      const saved = localStorage.getItem(ADVANCED_SETTINGS_STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        return {
          optimizedKernel: parsed.optimizedKernel ?? true,
          skipDuplicateHashOnCrack: parsed.skipDuplicateHashOnCrack ?? true,
          workloadProfile: parsed.workloadProfile ?? 3,
          deviceTypes: parsed.deviceTypes ?? ["2"],
          deviceIds: parsed.deviceIds ?? "",
        };
      }
    } catch (e) {
      console.error("Failed to load advanced settings:", e);
    }
    return { optimizedKernel: true, skipDuplicateHashOnCrack: true, workloadProfile: 3, deviceTypes: ["2"], deviceIds: "" };
  };

  const savedSettings = loadAdvancedSettings();

  const [optimizedKernel, setOptimizedKernel] = useState(savedSettings.optimizedKernel);
  const [skipDuplicateHashOnCrack, setSkipDuplicateHashOnCrack] = useState(savedSettings.skipDuplicateHashOnCrack);
  const [workloadProfile, setWorkloadProfile] = useState(savedSettings.workloadProfile);
  const [deviceTypes, setDeviceTypes] = useState<string[]>(savedSettings.deviceTypes);
  const [deviceIds, setDeviceIds] = useState(savedSettings.deviceIds);
  const [latestStatus, setLatestStatus] = useState<Record<string, unknown> | null>(null);
  const [lastSpeedHps, setLastSpeedHps] = useState<number | undefined>(undefined);
  const [deviceScanState, setDeviceScanState] = useState<"idle" | "scanning" | "done" | "error">("idle");
  const [backendCommand, setBackendCommand] = useState("");
  const [resourceQuery, setResourceQuery] = useState("");
  const [resourceTypeFilter, setResourceTypeFilter] = useState("");
  const [identifyModes, setIdentifyModes] = useState<HashModeInfo[]>([]);
  const [identifyRaw, setIdentifyRaw] = useState("");
  const [identifyRunning, setIdentifyRunning] = useState(false);


  useEffect(() => {
    const settings = {
      optimizedKernel,
      skipDuplicateHashOnCrack,
      workloadProfile,
      deviceTypes,
      deviceIds,
    };
    localStorage.setItem(ADVANCED_SETTINGS_STORAGE_KEY, JSON.stringify(settings));
  }, [optimizedKernel, skipDuplicateHashOnCrack, workloadProfile, deviceTypes, deviceIds]);

  const [aiSettings, setAiSettings] = useState<AiSettings>({
    baseUrl: "https://api.openai.com/v1",
    apiKey: "",
    model: "gpt-4o-mini",
  });
  const [aiOpen, setAiOpen] = useState(false);
  const [aiMinimized, setAiMinimized] = useState(false);
  const [aiRunningTaskIds, setAiRunningTaskIds] = useState<string[]>([]);
  const [aiTaskId, setAiTaskId] = useState("");
  const [aiTextByTask, setAiTextByTask] = useState<Record<string, string>>({});
  const [aiErrorByTask, setAiErrorByTask] = useState<Record<string, string>>({});

  const [attackSequence, setAttackSequence] = useState<AttackSequenceItem[]>([]);

  const selectedTask = tasks.find((task) => task.taskId === selectedTaskId);
  const selectedResults = selectedTaskId && resultsTaskId === selectedTaskId ? results : null;
  const selectedTaskLog = taskLogTaskId === selectedTaskId ? taskLog : null;
  const aiText = normalizeAiAnalysisText(aiTextByTask[aiTaskId] ?? "").trimStart();
  const aiError = aiErrorByTask[aiTaskId] ?? "";
  const aiWindowRunning = aiRunningTaskIds.includes(aiTaskId);
  const queueStartingRef = useRef(false);
  const text = useMemo<UiText>(() => language === "zh" ? ZH_TEXT : UI_TEXT.en, [language]);
  const filteredModes = useMemo(() => filterModes(hashModes, modeQuery), [hashModes, modeQuery]);
  const filteredResources = useMemo(
    () => resources.filter((item) => {
      // 类型过滤
      if (resourceTypeFilter && item.kind !== resourceTypeFilter) {
        return false;
      }
      // 搜索过滤
      return `${item.kind} ${item.name}`.toLowerCase().includes(resourceQuery.toLowerCase());
    }),
    [resources, resourceQuery, resourceTypeFilter],
  );
  const hashSuggestions = useMemo(
    () => recommendHashModes(hashText, hashModes),
    [hashText, hashModes],
  );
  const preview = backendCommand || buildPreview({
    attackMode,
    dictionaryPath,
    dictionaryPath2,
    leftRule,
    rightRule,
    useLeftRule: attackMode === 0 ? useRules : useLeftRule,
    useRightRule,
    hashFile,
    hashMode,
    hashText,
    mask,
    maskFile,
    templatePrefixMask,
    templateSuffixMask,
    increment,
    incrementMin: numberOrNull(incrementMin),
    incrementMax: numberOrNull(incrementMax),
    customCharset1: charsetEnabled ? customCharset1 : "",
    customCharset2: charsetEnabled ? customCharset2 : "",
    customCharset3: charsetEnabled ? customCharset3 : "",
    customCharset4: charsetEnabled ? customCharset4 : "",
    charsetFile1: charsetEnabled ? charsetFile1 : "",
    charsetFile2: charsetEnabled ? charsetFile2 : "",
    charsetFile3: charsetEnabled ? charsetFile3 : "",
    charsetFile4: charsetEnabled ? charsetFile4 : "",
    optimizedKernel,
    rulePaths: useRules ? rulePaths : [],
    workloadProfile,
    deviceTypes,
    deviceIds,
  });
  const [maskFileCandidates, setMaskFileCandidates] = useState<bigint | null>(null);
  const maskEstimate = useMemo(
    () => {
      const baseEstimate = estimateAttackMask({
        attackMode,
        mask,
        templatePrefixMask,
        templateSuffixMask,
        customCharsets: [customCharset1, customCharset2, customCharset3, customCharset4],
        increment,
        incrementMin,
        incrementMax,
        speedHps: lastSpeedHps,
        text,
      });
      
      // 如果有掩码文件的估算结果，使用掩码文件的结果
      if (attackMode === 3 && maskFile && maskFileCandidates !== null) {
        return {
          ...baseEstimate,
          candidates: maskFileCandidates,
          estimatedSeconds: lastSpeedHps && maskFileCandidates 
            ? Number(maskFileCandidates / BigInt(lastSpeedHps)) 
            : undefined,
        };
      }
      
      return baseEstimate;
    },
    [attackMode, mask, templatePrefixMask, templateSuffixMask, customCharset1, customCharset2, customCharset3, customCharset4, lastSpeedHps, text, maskFile, maskFileCandidates, increment, incrementMin, incrementMax],
  );

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const dropdown = document.querySelector('.hash-mode-list');
      const trigger = document.querySelector('.hash-mode-dropdown-trigger');
      const dropdownContainer = document.querySelector('.hash-mode-dropdown');
      
      if (dropdown && !dropdown.contains(event.target as Node) && 
          trigger && !trigger.contains(event.target as Node) &&
          dropdownContainer && !dropdownContainer.contains(event.target as Node)) {
        dropdown.classList.remove('open');
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  useEffect(() => {
    if (!isTauriRuntime) {
      setError("This page requires the desktop runtime. Please open the app in Tauri instead of the browser.");
      return;
    }
    void refreshStartup();
  }, []);

  useEffect(() => {
    localStorage.setItem(LANGUAGE_STORAGE_KEY, language);
    document.documentElement.lang = language === "zh" ? "zh-CN" : "en";
  }, [language]);

  useEffect(() => {
    if (customResources.length > 0) {
      invoke("write_custom_resources_file", { resourcesJson: JSON.stringify(customResources) })
        .catch(console.error);
    }
  }, [customResources]);

  useEffect(() => {
    // 将 BigInt 转换为字符串以便 JSON 序列化
    const replacer = (_key: string, value: unknown): unknown => {
      if (typeof value === 'bigint') {
        return value.toString();
      }
      return value;
    };
    localStorage.setItem(TASK_QUEUE_STORAGE_KEY, JSON.stringify(queueItems, replacer));
  }, [queueItems]);

  useEffect(() => {
    if (attackMode === 3 && maskFile) {
      async function calculate() {
        try {
          let total: number;
          if (increment) {
            // 启用递增
            const minValue = incrementMin ? parseInt(incrementMin, 10) : NaN;
            const maxValue = incrementMax ? parseInt(incrementMax, 10) : NaN;
            
            const min = Number.isNaN(minValue) ? 1 : minValue;
            const max = Number.isNaN(maxValue) ? 0 : maxValue;  // 0 表示使用掩码长度
            
            total = await invoke<number>("count_mask_file_candidates_with_increment", {
                path: maskFile,
                enableIncrement: true,
                incrementMin: min,
                incrementMax: max,
            });
          } else {
            // 不启用递增
            total = await invoke<number>("count_mask_file_candidates_with_increment", {
                path: maskFile,
                enableIncrement: false,
                incrementMin: 1,
                incrementMax: 0,
            });
          }
          setMaskFileCandidates(BigInt(total));
        } catch (err) {
          console.error("Failed to estimate mask file candidates:", err);
          setMaskFileCandidates(null);
        }
      }
      void calculate();
    } else {
      setMaskFileCandidates(null);
    }
  }, [attackMode, maskFile, increment, incrementMin, incrementMax]);

  useEffect(() => {
    if (queuePaused || running || queueStartingRef.current) return;
    const next = queueItems.find((item) => item.status === "pending" || item.status === "stopped");
    if (next) void startQueuedItem(next);
  }, [queueItems, queuePaused, running]);

  useEffect(() => {
    if (!isTauriRuntime) {
      return;
    }

    const unlisteners: UnlistenFn[] = [];
    let unlistenDrop: UnlistenFn | undefined;
    let disposed = false;

    function register<T>(eventName: string, handler: (event: Event<T>) => void | Promise<void>) {
      tauriListen<T>(eventName, handler).then((unlisten) => {
        if (disposed) {
          unlisten();
          return;
        }
        unlisteners.push(unlisten);
      }).catch((err) => setError(String(err)));
    }

    register<LogPayload>("hashcat-log", (event) => {
      setLogs((current) => [...current.slice(-400), event.payload]);
    });

    register<StatusPayload>("hashcat-status", (event) => {
      if (event.payload.taskId === taskId || event.payload.taskId === selectedTaskId) {
        setLatestStatus(event.payload.data);
        const speed = extractStatusSpeed(event.payload.data);
        if (speed) setLastSpeedHps(speed);
      }
    });

    register<ExitPayload>("hashcat-exit", async (event) => {
      setRunning(false);
      setStopping(false);
      setTaskId("");
      setSelectedTaskId(event.payload.taskId);
      
      // ========== 新增：检测破解结果 ==========
      let hasCracked = false;
      try {
          const result = await invoke<ResultsResponse>("read_results", { taskId: event.payload.taskId });
          hasCracked = !!(result.content && result.content.trim().length > 0);
          
          // 如果破解成功，提取密码并保存到 localStorage
          if (hasCracked && result.content) {
              const extractedPasswords = extractPasswordsFromResults(result.content);
              if (extractedPasswords.length > 0) {
                  saveExtractedPasswords(event.payload.taskId, extractedPasswords);
              }
          }
      } catch {
          hasCracked = false;
      }
      // ========== 检测结束 ==========

      // 在移除队列项之前，保存其 candidates 和 isEstimated 值
      const completedItem = queueItems.find(item => item.taskId === event.payload.taskId);
      const savedCandidates = completedItem?.candidates;
      const savedIsEstimated = completedItem?.isEstimated;

      setQueueItems((current) => {
        return current
          .map((item) => {
            if (item.taskId === event.payload.taskId) {
              if (item.status === "stopped") {
                return item;
              }
              if (item.status === "running") {
                const exitCode = event.payload.code;
                const isSuccess = exitCode === 0 || exitCode === null;
                return {
                  ...item,
                  status: isSuccess ? "finished" as QueueStatus : "failed" as QueueStatus,
                  finishedAt: new Date().toISOString(),
                  error: isSuccess ? undefined : event.payload.reason,
                };
              }
            }

            // ========== 破解成功时跳过后续任务 ==========
            if (hasCracked && item.status === "pending") {
              // 原有逻辑：相同组的多字典/多序列任务
              const sameGroup = completedItem?.groupId && item.groupId === completedItem.groupId &&
                  (item.id.startsWith("multi-dict-") || item.id.startsWith("multi-seq-"));
              
              // 新增逻辑：比对已保存的 hashContent
              const completedHash = completedItem?.hashContent || 
                                    normalizeHashContent(completedItem?.config.hashText) || 
                                    normalizeHashContent(completedItem?.config.hashFile);
              const itemHash = item.hashContent || 
                              normalizeHashContent(item.config.hashText) || 
                              normalizeHashContent(item.config.hashFile);
              const sameHash = skipDuplicateHashOnCrack && completedHash && itemHash && completedHash === itemHash;
              
              if (sameGroup || sameHash) {
                return {
                  ...item,
                  status: "skipped" as QueueStatus,
                  finishedAt: new Date().toISOString(),
                };
              }
            }
            // ========== 跳过逻辑结束 ==========
            return item;
          })
          .filter(item => 
            item.taskId !== event.payload.taskId || 
            (item.status !== "finished" && item.status !== "failed")
          );
      });
      
      // 只有当任务不是暂停状态时才刷新历史
      const queuedItem = queueItems.find(item => item.taskId === event.payload.taskId);
      if (!queuedItem || queuedItem.status !== "stopped") {
        await Promise.all([refreshTasks(), readResultsFor(event.payload.taskId), readTaskLogFor(event.payload.taskId)]);
        // 将队列中的 candidates 和 isEstimated 值同步到历史任务中
        if (savedCandidates !== undefined && completedItem?.status !== "stopped") {
          // 先保存到 localStorage（使用字符串存储 bigint）
          try {
            const savedCandidatesData: Record<string, { candidates: string; isEstimated: boolean }> = JSON.parse(
              localStorage.getItem(TASK_CANDIDATES_STORAGE_KEY) || "{}"
            );
            savedCandidatesData[event.payload.taskId] = {
              candidates: typeof savedCandidates === "bigint" ? savedCandidates.toString() : String(savedCandidates),
              isEstimated: savedIsEstimated || false,
            };
            localStorage.setItem(TASK_CANDIDATES_STORAGE_KEY, JSON.stringify(savedCandidatesData));
          } catch (e) {
            console.error("Failed to save candidates:", e);
          }
          
          setTasks((current) => {
            return current.map((task) => {
              if (task.taskId === event.payload.taskId) {
                const newName = completedItem?.name || task.taskName;
                // 保存到任务名称映射
                saveTaskName(event.payload.taskId, newName);
                return {
                  ...task,
                  taskName: newName,  // 同步队列中修改的任务名称
                  config: {
                    ...task.config,
                    candidates: savedCandidates,
                    isEstimated: savedIsEstimated,
                  },
                };
              }
              return task;
            });
          });
        }
      }
      
      showToast(text.taskFinished.replace("{status}", statusLabel(event.payload.reason, language)));
    });

    register<AiAnalysisEvent>("ai-analysis-start", (event) => {
      setAiTaskId(event.payload.taskId);
      setAiTextByTask((current) => ({ ...current, [event.payload.taskId]: "" }));
      setAiErrorByTask((current) => ({ ...current, [event.payload.taskId]: "" }));
      setAiRunningTaskIds((current) =>
        current.includes(event.payload.taskId) ? current : [...current, event.payload.taskId],
      );
      setAiOpen(true);
      setAiMinimized(false);
    });

    register<AiAnalysisEvent>("ai-analysis-delta", (event) => {
      setAiTaskId(event.payload.taskId);
      setAiTextByTask((current) => ({
        ...current,
        [event.payload.taskId]: appendAiDelta(current[event.payload.taskId] ?? "", event.payload.text ?? ""),
      }));
    });

    register<AiAnalysisEvent>("ai-analysis-error", (event) => {
      setAiTaskId(event.payload.taskId);
      setAiErrorByTask((current) => ({ ...current, [event.payload.taskId]: event.payload.error ?? `${text.aiAnalyze} failed` }));
      setAiRunningTaskIds((current) => current.filter((taskId) => taskId !== event.payload.taskId));
      setAiOpen(true);
      setAiMinimized(false);
    });

    register<AiAnalysisEvent>("ai-analysis-finish", (event) => {
      setAiRunningTaskIds((current) => current.filter((taskId) => taskId !== event.payload.taskId));
    });

    register<HashcatUpdateEvent>("hashcat-update-log", (event) => {
      setUpdateLogs((current) => mergeUpdateLog(current, event.payload));
    });

    register<HashcatUpdateFinishEvent>("hashcat-update-finish", async (event) => {
      setUpdateRunning(false);
      if (!event.payload.ok) {
        setError(event.payload.error ?? "hashcat update failed");
        return;
      }
      if (event.payload.info) setUpdateInfo(event.payload.info);
      await Promise.all([refreshInfo(), refreshHashcatPathStatus()]);
      showToast(text.hashcatUpdate);
    });
    // Only register drag-drop event handler in Tauri environment
    if (isTauriRuntime) {
      getCurrentWebview().onDragDropEvent((event) => {
        if (event.payload.type !== "drop") return;
        // 获取拖放的文件路径
        const paths = event.payload.paths || [];
        if (paths.length === 0) return;
        
        // Tauri 的 position 是设备像素坐标，需要转换为 CSS 像素坐标
        const { x, y } = event.payload.position;
        const dpr = window.devicePixelRatio || 1;
        const viewportX = (x / dpr) - window.scrollX;
        const viewportY = (y / dpr) - window.scrollY;
        const elements = document.elementsFromPoint(viewportX, viewportY);
        
        // 检查是否在 hash 文件区域
        const hashInput = elements.find((el: any) => el.classList?.contains('hash-input-file') || el.closest?.('.hash-input-file'));
        if (hashInput) {
          const lowerPath = paths[0].toLowerCase();
          
          // 检测 PCAP 文件
          if (lowerPath.endsWith(".cap") || lowerPath.endsWith(".pcap") || lowerPath.endsWith(".pcapng") || lowerPath.endsWith(".hccapx")) {
            handleCapAndHccapxFile(paths[0]);
            return;
          }
          
          setHashFile(paths[0]);
          setHashText("");
          
          // 检测hash是否已破解
          void (async () => {
            try {
              const response = await invoke<FilePreviewResponse>("preview_text_file", {
                path: paths[0],
                allowFull: true
              });
              const crackedTaskId = await checkHashAlreadyCracked(response.content || "", tasks);
              if (crackedTaskId) {
                const crackedTask = tasks.find(t => t.taskId === crackedTaskId);
                const passwords = crackedTask?.extractedPasswords?.slice(0, 3) || [];
                const passwordText = passwords.length > 0 
                  ? `\n${text.passwordLabel}: ${passwords.join(", ")}` 
                  : "";
                const message = `${text.hashAlreadyCracked}${passwordText}`;
                setError(message);
              }
            } catch {
              // 文件读取失败，跳过检测
            }
          })();

          if (lowerPath.endsWith(".hc22000")) {
            setHashMode("22000");
            handleHc22000File(paths[0]);
          } else {
            setHc22000Info(null);
          }
          
          return;
        }
        
        // 检查是否在字典组合模式的右字典区域
        const dictComboRight = elements.find((el: any) => {
          const closest = el.closest?.('.dictionary-combo .attack-side-by-side:last-child .attack-left');
          return closest;
        });
        if (dictComboRight) {
          setDictionaryPath2(paths[0]);
          return;
        }
        
        // 检查是否在掩码+字典模式(attackMode=7)的字典区域
        const maskDictRight = elements.find((el: any) => {
          const closest = el.closest?.('.attack-side-by-side .attack-right .resource-line');
          return closest;
        });
        if (maskDictRight) {
          setDictionaryPath(paths[0]);
          return;
        }
        
        // 检查是否在普通字典区域（字典模式、字典组合左字典、字典+掩码模式）
        const dictInput = elements.find((el: any) => {
          const attackLeft = el.classList?.contains('attack-left') ? el : el.closest?.('.attack-left');
          return attackLeft && attackLeft.querySelector?.('.resource-line');
        });
        if (dictInput) {
          setDictionaryPath(paths[0]);
          return;
        }
      }).then((unlisten) => {
        if (disposed) {
          unlisten();
          return;
        }
        unlistenDrop = unlisten;
      });
    }

    return () => {
      disposed = true;
      unlisteners.forEach((unlisten) => unlisten());
      unlistenDrop?.();
    };
  }, [attackMode, dictionaryPath, selectedTaskId, language, text]);

  useEffect(() => {
    // 检查预设中的文件
    const checkPresets = async () => {
      const checkedPresets = await Promise.all(
        presets.map(async preset => ({
          ...preset,
          isValid: await checkPresetFiles(preset),
        }))
      );
      setPresets(checkedPresets);
    };
    
    checkPresets();
  }, []); // 只在挂载时执行一次

  async function refreshStartup() {
    setResults(null);
    setResultsTaskId("");
    setTaskLog(null);
    setTaskLogTaskId("");
    await refreshTasks();
    setSelectedTaskId("");
    await Promise.all([refreshInfo(), refreshResources(), refreshAiSettings(), refreshHashcatPathStatus()]);
    window.setTimeout(() => void refreshHashModes(), 300);
  }

  async function refreshCurrentData() {
    const nextTasks = await refreshTasks();
    const nextSelectedTaskId = selectedTaskId || nextTasks[0]?.taskId || "";
    
    // 检查预设文件
    const checkedPresets = await Promise.all(
      presets.map(async preset => ({
        ...preset,
        isValid: await checkPresetFiles(preset),
      }))
    );
    setPresets(checkedPresets);
    
    await Promise.all([refreshInfo(), refreshResources(), refreshAiSettings(), refreshHashcatPathStatus()]);
    if (nextSelectedTaskId) await Promise.all([readResultsFor(nextSelectedTaskId), readTaskLogFor(nextSelectedTaskId)]);
    window.setTimeout(() => void refreshHashModes(), 300);
  }

  async function refreshInfo() {
    try {
      const next = await invoke<HashcatInfo>("get_hashcat_info", { includeBackendInfo: false });
      setInfo(next);
      if (next.error) setError(next.error);
    } catch (err) {
      setError(String(err));
    }
  }

  async function refreshDeviceInfo() {
    setDeviceScanState("scanning");
    try {
      const next = await invoke<HashcatInfo>("get_hashcat_info", { includeBackendInfo: true });
      setInfo(next);
      if (next.error) setError(next.error);
      setDeviceScanState(next.error ? "error" : "done");
    } catch (err) {
      setError(String(err));
      setDeviceScanState("error");
    }
  }

  async function checkHashcatUpdate() {
    setUpdateLogs((current) => mergeUpdateLog(current, { phase: "check", line: text.checkUpdate }));
    try {
      const next = await invoke<HashcatUpdateInfo>("check_hashcat_update");
      setUpdateInfo(next);
      setUpdateLogs((current) => mergeUpdateLog(current, {
        phase: "check",
        line: `${text.updateCurrent}: ${next.currentVersion ?? "-"} / ${text.updateLatest}: ${next.latestVersion}`,
      }));
    } catch (err) {
      setError(String(err));
      setUpdateLogs((current) => mergeUpdateLog(current, { phase: "error", line: String(err) }));
    }
  }

  async function installHashcatUpdate() {
    setUpdateRunning(true);
    setUpdateLogs([{ phase: "start", line: text.updateRunning }]);
    try {
      await invoke("install_hashcat_update");
    } catch (err) {
      setUpdateRunning(false);
      setError(String(err));
      setUpdateLogs((current) => mergeUpdateLog(current, { phase: "error", line: String(err) }));
    }
  }

  async function refreshHashModes() {
    try {
      setHashModes(await invoke<HashModeInfo[]>("get_hash_modes"));
    } catch (err) {
      setError(String(err));
    }
  }

  async function identifyHash() {
    setIdentifyRunning(true);
    setIdentifyRaw("");
    setIdentifyModes([]);
    try {
      const response = await invoke<IdentifyResponse>("identify_hash", { hashText, hashFile });
      setIdentifyRaw(response.raw);
      setIdentifyModes(response.modes);
    } catch (err) {
      setError(String(err));
    } finally {
      setIdentifyRunning(false);
    }
  }

  async function checkPresetFiles(preset: PresetConfig): Promise<boolean> {
    const pathsToCheck: string[] = [];
    
    // 收集所有需要检查的文件路径
    if (preset.dictionaryPath) pathsToCheck.push(preset.dictionaryPath);
    if (preset.dictionaryPath2) pathsToCheck.push(preset.dictionaryPath2);
    if (preset.dictionaryPaths) pathsToCheck.push(...preset.dictionaryPaths);
    if (preset.maskPath) pathsToCheck.push(preset.maskPath);
    if (preset.rulePaths) pathsToCheck.push(...preset.rulePaths);
    
    // 如果没有需要检查的路径，视为有效
    if (pathsToCheck.length === 0) return true;
    
    // 检查所有路径
    const results = await Promise.all(
      pathsToCheck.map(path => invoke<boolean>("check_file_exists", { path }))
    );
    
    // 所有文件都存在才视为有效
    return results.every(exists => exists);
  }


  // 检查单个文件是否存在
  async function checkFileExists(path: string): Promise<boolean> {
    return invoke<boolean>("check_file_exists", { path });
  }

  // 检查多个文件并返回不存在的文件列表
  async function checkFilesExist(paths: string[]): Promise<string[]> {
    const results = await Promise.all(
      paths.map(async path => ({
        path,
        exists: await checkFileExists(path),
      }))
    );
    return results.filter(r => !r.exists).map(r => r.path);
  }

  // 从攻击配置中提取所有文件路径
  function extractFilePaths(config: AttackConfig): string[] {
    const pathSet = new Set<string>(); // 使用 Set 自动去重
    
    // 字典路径
    if (config.dictionaryPath) pathSet.add(config.dictionaryPath);
    if (config.dictionaryPath2) pathSet.add(config.dictionaryPath2);
    if (config.dictionaryPaths) config.dictionaryPaths.forEach(p => pathSet.add(p));
    
    // 掩码文件
    if (config.maskFile) pathSet.add(config.maskFile);
    
    // 规则文件
    if (config.rulePaths) config.rulePaths.forEach(p => pathSet.add(p));
    
    // 字符集文件
    if (config.charsetFile1) pathSet.add(config.charsetFile1);
    if (config.charsetFile2) pathSet.add(config.charsetFile2);
    if (config.charsetFile3) pathSet.add(config.charsetFile3);
    if (config.charsetFile4) pathSet.add(config.charsetFile4);
    
    return Array.from(pathSet); // 转换为数组返回
  }

  async function refreshResources() {
    try {
      // 新增：从后端读取自定义资源数据
      const [builtin, user, customResourcesData] = await Promise.all([
        invoke<ResourceInfo[]>("list_builtin_resources"),
        invoke<UserDictionary[]>("list_user_dictionaries"),
        invoke<string>("read_custom_resources_file"),
      ]);
      
      // 新增：解析从后端读取的数据
      const customResourcesFromBackend = customResourcesData ? JSON.parse(customResourcesData) : [];
      
      // 检查内置资源文件是否存在
      const checkedBuiltin = await Promise.all(builtin.map(async (resource) => ({
        ...resource,
        isValid: await invoke<boolean>("check_file_exists", { path: resource.path }),
      })));
      
      // 检查用户字典文件是否存在
      const checkedUser = await Promise.all(user.map(async (dict) => ({
        ...dict,
        isValid: await invoke<boolean>("check_file_exists", { path: dict.path }),
      })));
      
      // 修改：使用从后端读取的数据，而不是状态
      const checkedCustomResources = await Promise.all(customResourcesFromBackend.map(async (resource: CustomResource) => {
        if (!resource.path) {
          return { ...resource, isValid: true };
        }
        return {
          ...resource,
          isValid: await invoke<boolean>("check_file_exists", { path: resource.path }),
        };
      }));
      
      setCustomResources(checkedCustomResources);
      setResources(checkedBuiltin);
      setUserDictionaries(checkedUser);
    } catch (err) {
      setError(String(err));
    }
  }

  async function refreshTasks() {
    try {
      // 1. 获取任务列表
      const next = await invoke<TaskManifest[]>("list_tasks");
      
      // 2. 过滤掉暂停和运行中的任务
      const filtered = next.filter(task => 
        task.status !== "stopped" && task.status !== "running"
      );
      
      // 3. 从 localStorage 读取保存的 candidates 和 isEstimated
      let savedCandidates: Record<string, { candidates: string; isEstimated: boolean }> = {};
      try {
        savedCandidates = JSON.parse(localStorage.getItem(TASK_CANDIDATES_STORAGE_KEY) || "{}");
      } catch (e) {
        console.error("Failed to load saved candidates:", e);
        savedCandidates = {};
      }

      // 4. 从 localStorage 读取保存的任务名称
      const savedNames = loadTaskNames();

      // 5. 找出需要提取密码的任务（已破解但未提取的），并行提取
      const tasksToExtract = filtered.filter(task => 
          task.status === "cracked" && !loadExtractedPasswords(task.taskId)
      );
      if (tasksToExtract.length > 0) {
          const extractPromises = tasksToExtract.map(task => 
              extractPasswordsForTask(task.taskId).catch(() => null)
          );
          await Promise.all(extractPromises);
      }

      // 6. 合并数据（核心优化：只从 localStorage 读取密码）
      const mergedTasks = filtered.map((newTask) => {
        const saved = savedCandidates[newTask.taskId];
        
        // 关键：只从 localStorage 读取已保存的密码，不调用 read_results
        const existingPasswords = loadExtractedPasswords(newTask.taskId);
        const savedCandidatesStr = saved?.candidates;
        const isValidCandidates = savedCandidatesStr != null && savedCandidatesStr !== "null" && savedCandidatesStr !== "undefined";
        
        const taskWithCandidates = saved && isValidCandidates ? {
          ...newTask,
          config: {
            ...newTask.config,
            candidates: BigInt(saved.candidates),
            isEstimated: saved.isEstimated,
          },
        } : newTask;
        
        return {
          ...taskWithCandidates,
          extractedPasswords: existingPasswords,  // 可能为 null（未提取）
          passwordsExtracted: existingPasswords !== null,
        };
      });

      // 7. 应用保存的任务名称
      const tasksWithNames = mergedTasks.map(task => ({
        ...task,
        taskName: savedNames[task.taskId] || task.taskName,
      }));
      
      setTasks(tasksWithNames);
      return tasksWithNames;
    } catch (err) {
      setError(String(err));
      return [];
    }
  }

  async function extractPasswordsForTask(taskId: string): Promise<string[] | null> {
      // 优先从 localStorage 读取，避免重复提取
      const existingPasswords = loadExtractedPasswords(taskId);
      if (existingPasswords) {
          return existingPasswords;
      }
      
      // 未提取过，调用后端 API
      try {
          const result = await invoke<ResultsResponse>("read_results", { taskId });
          if (result && result.content) {
              const extractedPasswords = extractPasswordsFromResults(result.content);
              if (extractedPasswords.length > 0) {
                  // 保存到 localStorage，后续不再重复提取
                  saveExtractedPasswords(taskId, extractedPasswords);
                  return extractedPasswords;
              }
          }
          return null;
      } catch (e) {
          console.error("Failed to extract passwords for task " + taskId + ":", e);
          return null;
      }
  }

  async function refreshAiSettings() {
    try {
      setAiSettings(await invoke<AiSettings>("get_ai_settings"));
    } catch (err) {
      setError(String(err));
    }
  }

  async function refreshHashcatPathStatus() {
    try {
      setHashcatPathStatus(await invoke<HashcatPathStatus>("get_hashcat_path_status"));
    } catch (err) {
      setError(String(err));
    }
  }

  const parseHc22000Content = useCallback((content: string): Hc22000Info | null => {
    const lines = content.trim().split(/\r?\n/).filter(line => line.trim());
    const lineCount = lines.length;
    
    if (lineCount === 0) return null;
    
    const entries: Hc22000Entry[] = [];
    
    for (const line of lines) {
      const parts = line.split('*');
      
      // 验证基本格式：至少需要 6 段（WPA*type*hash*bssid*ap_mac*essid*...）
      if (parts.length < 6) {
        console.log("跳过无效行：段数不足", parts.length);
        continue;
      }
      
      // 验证第一段：固定为 WPA
      if (parts[0] !== "WPA") {
        console.log("跳过无效行：不是 WPA 格式");
        continue;
      }
      
      // 验证第二段：type 必须为 01 或 02
      const type = parts[1];
      if (type !== "01" && type !== "02") {
        console.log("跳过无效行：type 不是 01 或 02，当前值:", type);
        continue;
      }
      
      // 验证第 4 段：BSSID 必须是 12 位十六进制字符
      const bssidHex = parts[3];
      if (!/^[0-9A-Fa-f]{12}$/.test(bssidHex)) {
        console.log("跳过无效行：BSSID 格式不正确，当前值:", bssidHex);
        continue;
      }
      
      // 验证第 5 段：AP_MAC 必须是 12 位十六进制字符
      const apMacHex = parts[4];
      if (!/^[0-9A-Fa-f]{12}$/.test(apMacHex)) {
        console.log("跳过无效行：AP_MAC 格式不正确，当前值:", apMacHex);
        continue;
      }
      
      // 验证第 6 段：ESSID 必须是偶数长度（0~64 位十六进制字符，即 0~32 字节）
      const essidHex = parts[5];
      if (essidHex.length % 2 !== 0 || essidHex.length > 64) {
        console.log("跳过无效行：ESSID 长度不正确，当前长度:", essidHex.length);
        continue;
      }
      
      // 验证 ESSID 是有效的十六进制字符串
      if (essidHex.length > 0 && !/^[0-9A-Fa-f]*$/.test(essidHex)) {
        console.log("跳过无效行：ESSID 包含非十六进制字符");
        continue;
      }
      
      // 解析 ESSID（十六进制转字符串）
      let essid = "";
      try {
        if (essidHex.length > 0) {
          const bytes = [];
          for (let i = 0; i < essidHex.length; i += 2) {
            bytes.push(parseInt(essidHex.substr(i, 2), 16));
          }
          essid = new TextDecoder('utf-8').decode(new Uint8Array(bytes));
        }
      } catch {
        essid = "Unknown";
      }
      
      // 格式化 MAC 地址
      const bssid = formatMacAddress(bssidHex);
      const apMac = formatMacAddress(apMacHex);
      
      entries.push({ essid, bssid, apMac, lineText: line });
    }
    
    // 如果没有解析到任何有效记录，返回 null
    if (entries.length === 0) return null;
    
    return { entries, lineCount };
  }, []);

  // 格式化 MAC 地址
  function formatMacAddress(hex: string): string {
    if (!hex || hex.length !== 12) return hex;
    return hex.match(/.{2}/g)?.join(':').toUpperCase() || hex;
  }

  // 处理 .hc22000 文件（同时支持选择和拖放）
  async function handleHc22000File(filePath: string) {
    try {
      // 使用正确的后端函数名读取文件
      const response = await invoke<FilePreviewResponse>("preview_text_file", { 
        path: filePath, 
        allowFull: true 
      });
      
      // 解析文件内容
      const info = parseHc22000Content(response.content);
      
      // 更新状态
      setHc22000Info(info);
      // 自动全选所有条目
      if (info && info.entries.length > 0) {
        setSelectedHc22000Indices(info.entries.map((_, i) => i));
        setHc22000SelectionMode('multi');
      }
    } catch (error) {
      // 出错时清空解析信息
      console.error("处理 .hc22000 文件失败:", error);
      setHc22000Info(null);
    }
  }

  // 处理 pcap/cap 文件转换
  async function handleCapAndHccapxFile(filePath: string) {
    try {
      const response = await invoke<{
        success: boolean;
        outputPath?: string;
        error?: string;
        cached: boolean;
      }>("convert_to_hc22000", { inputPath: filePath });
      
      if (response.success && response.outputPath) {
        setHashFile(response.outputPath);
        setOriginalHashFile(filePath);
        setHashText("");
        setHashMode("22000");
        handleHc22000File(response.outputPath);
        
        if (response.cached) {
          showToast(text.Convert2hc22000Cached); 
        } else {
          showToast(text.Convert2hc22000Success); 
        }
      } else {
        setOriginalHashFile("");
        setHc22000Info(null);
        setError(text.Convert2hc22000Failed);
      }
    } catch (error) {
      setOriginalHashFile("");
      setHc22000Info(null);
      setError(`${text.Convert2hc22000Failed}: ${error}`);
    }
  }

  useEffect(() => {
  if (!hashFile && hashText.trim()) {
      const info = parseHc22000Content(hashText);
      setHc22000Info(info);
      
      // 自动全选所有条目
      if (info && info.entries.length > 0) {
      setSelectedHc22000Indices(info.entries.map((_, i) => i));
      setHc22000SelectionMode('multi');
      }
      
      if (info) {
      setHashMode("22000");
      }
  } else if (!hashFile && !hashText.trim()) {
      setHc22000Info(null);
      setSelectedHc22000Indices([]);
  }
  }, [hashText, hashFile, parseHc22000Content]);

  // 修改 chooseHashFile 函数使用新的处理函数
  async function chooseHashFile() {
    const selected = await open({ multiple: false, directory: false });
    if (typeof selected === "string") {
      const lowerPath = selected.toLowerCase();
      
      // 检测 PCAP 文件
      if (lowerPath.endsWith(".cap") || lowerPath.endsWith(".pcap") || lowerPath.endsWith(".pcapng") || lowerPath.endsWith(".hccapx")) {
        await handleCapAndHccapxFile(selected);
        return;
      }
      
      setHashFile(selected);
      setHashText("");
      
      // 检测hash是否已破解
      void (async () => {
        try {
          const response = await invoke<FilePreviewResponse>("preview_text_file", {
            path: selected,
            allowFull: true
          });
          const crackedTaskId = await checkHashAlreadyCracked(response.content || "", tasks);
          if (crackedTaskId) {
            const crackedTask = tasks.find(t => t.taskId === crackedTaskId);
            const passwords = crackedTask?.extractedPasswords?.slice(0, 3) || [];
            const passwordText = passwords.length > 0 
              ? `\n${text.passwordLabel}: ${passwords.join(", ")}` 
              : "";
            const message = `${text.hashAlreadyCracked}${passwordText}`;
            setError(message);
          }
        } catch {
          // 文件读取失败，跳过检测
        }
      })();

      if (lowerPath.endsWith(".hc22000")) {
        setHashMode("22000");
        handleHc22000File(selected);
      } else {
        setHc22000Info(null);
      }
    }
  }

  async function chooseDictionary(target: "primary" | "secondary") {
    const selected = await open({ multiple: false, directory: false });
    if (typeof selected === "string") {
      if (target === "primary") {
        setDictionaryPath(selected);
      } else {
        setDictionaryPath2(selected);
      }
    }
  }

  // 选择多个字典（支持单选和多选）
  async function chooseMultipleDictionaries() {
      const selected = await open({ multiple: true, directory: false });
      const paths = Array.isArray(selected) ? selected : typeof selected === "string" ? [selected] : [];
      
      if (paths.length > 0) {
          setDictionaryPaths((current) => {
              const combined = [...new Set([...current, ...paths])];
              
              // 如果只有一个字典，同时设置单字典路径（保持向后兼容）
              if (combined.length === 1) {
                  setDictionaryPath(combined[0]);
              } else {
                  // 多个字典时清空单字典路径
                  setDictionaryPath("");
              }
              
              return combined;
          });
      }
  }

  // 移除单个字典
  function removeDictionaryFromList(path: string) {
      setDictionaryPaths((current) => {
          const updated = current.filter(p => p !== path);
          
          // 如果移除后只剩一个字典，设置为单字典模式
          if (updated.length === 1) {
              setDictionaryPath(updated[0]);
          } else if (updated.length === 0) {
              // 清空所有字典
              setDictionaryPath("");
          }
          
          return updated;
      });
  }

  // 清空字典列表
  function clearDictionaryPaths() {
      setDictionaryPaths([]);
      setDictionaryPath("");
  }

  // 上移字典
  function moveDictionaryUp(index: number) {
      setDictionaryPaths((current) => {
          if (index <= 0) return current;
          const newPaths = [...current];
          [newPaths[index - 1], newPaths[index]] = [newPaths[index], newPaths[index - 1]];
          return newPaths;
      });
  }

  // 下移字典
  function moveDictionaryDown(index: number) {
      setDictionaryPaths((current) => {
          if (index >= current.length - 1) return current;
          const newPaths = [...current];
          [newPaths[index], newPaths[index + 1]] = [newPaths[index + 1], newPaths[index]];
          return newPaths;
      });
  }

  // 置顶字典
  function moveDictionaryToTop(index: number) {
      setDictionaryPaths((current) => {
          if (index <= 0) return current;
          const newPaths = [...current];
          const [removed] = newPaths.splice(index, 1);
          newPaths.unshift(removed);
          return newPaths;
      });
  }

  // 置底字典
  function moveDictionaryToBottom(index: number) {
      setDictionaryPaths((current) => {
          if (index >= current.length - 1) return current;
          const newPaths = [...current];
          const [removed] = newPaths.splice(index, 1);
          newPaths.push(removed);
          return newPaths;
      });
  }

  async function chooseRules() {
    const selected = await open({ multiple: true, directory: false });
    const paths = Array.isArray(selected) ? selected : typeof selected === "string" ? [selected] : [];
    setRulePaths((current) => [...new Set([...current, ...paths])]);
    if (paths.length) setAttackMode(0);
  }


  async function chooseMaskFile() {
    const selected = await open({ multiple: false, directory: false });
    if (typeof selected === "string") {
      if (attackMode === 0) setAttackMode(3);
      setMaskFile(selected);
      setCharsetEnabled(false);
    }
  }

  async function useDictionary(path: string, remember: boolean) {

    // 检查文件是否存在
    const exists = await invoke('check_file_exists', { path });
    if (!exists) {
      const errorMsg = language === "zh"
        ? `文件不存在：${path}`
        : `File does not exist: ${path}`;
      setError(errorMsg);
      return;
    }

    if (attackMode === 3) setAttackMode(0);
    
    // ========== 字典攻击模式（模式-0）：支持多字典添加 ==========
    if (attackMode === 0) {
        setDictionaryPaths((current) => {
            const updated = [...new Set([...current, path])];
            // 如果只有一个字典，同时设置单字典路径（保持向后兼容）
            if (updated.length === 1) {
                setDictionaryPath(updated[0]);
            } else {
                // 多个字典时清空单字典路径
                setDictionaryPath("");
            }
            return updated;
        });
    } 
    // ========== 其他模式（字典组合、混合攻击等）：使用原有逻辑 ==========
    else {
        if (selectedResourceTarget === "primary") {
            setDictionaryPath(path);
        } else {
            setDictionaryPath2(path);
        }
    }
    
    if (!remember) return;
    try {
        setUserDictionaries(await invoke<UserDictionary[]>("add_user_dictionary", { path }));
    } catch (err) {
        setError(String(err));
    }
  }

  async function removeDictionary(path: string) {
    try {
      setUserDictionaries(await invoke<UserDictionary[]>("remove_user_dictionary", { path }));
      if (dictionaryPath === path) setDictionaryPath("");
    } catch (err) {
      setError(String(err));
    }
  }

  // 更新用户字典名称
  function updateUserDictionaryName(path: string, newName: string) {
    setUserDictionaries(prev => prev.map(d => 
      d.path === path ? { ...d, name: newName } : d
    ));
  }

  function handleAttackModeChange(mode: AttackMode) {
    setAttackMode(mode);
    // 根据目标模式清理不相关字段
    if (mode === 0) {
      // 字典攻击：清空掩码相关
      setMask("");
      setMaskFile("");
    } else if (mode === 3) {
      // 掩码攻击：清空字典和规则
      setDictionaryPath("");
      setRulePaths([]);
    } else if (mode === 9) {
      // 模板攻击：清空掩码、字典、规则
      setMask("");
      setMaskFile("");
      setDictionaryPath("");
      setRulePaths([]);
    }
    // 模式 6 和 7（Hybrid）不需要清理，因为需要同时使用字典和掩码
  }

  
  async function startAttack() {
    if (!hashFile && !hashText) {
      setError(text.missingHash);
      return;
    }
    const hasSequence  = attackSequence.length > 0;
    if (!hasSequence) {
      const configResult = isValidConfig();
      if (!configResult.valid) {
        // 校验失败，显示错误提示
        if (configResult.error) {
          setError(configResult.error);
        }
        return;
      }
    }

    // 提取所有文件路径
    const filePaths = extractFilePaths(currentConfig());
    
    // 检查文件是否存在
    const missingFiles = await checkFilesExist(filePaths);
    
    // 如果有文件不存在，显示错误提示
    if (missingFiles.length > 0) {
      const errorMsg = language === "zh" 
        ? `以下文件不存在：\n${missingFiles.join('\n')}`
        : `The following files do not exist:\n${missingFiles.join('\n')}`;
      setError(errorMsg);
      return;
    }
    
    setError("");
    setLogs([]);
    setLatestStatus(null);
    setBackendCommand("");

    // ========== 新增：读取并保存 hash 内容 ==========
    let taskHashContent = "";
    if (hashText?.trim()) {
      taskHashContent = normalizeHashContent(hashText);
    } else if (hashFile) {
      try {
        const response = await invoke<FilePreviewResponse>("preview_text_file", {
          path: hashFile,
          allowFull: true
        });
        taskHashContent = normalizeHashContent(response.content);
      } catch {
        // 如果读取失败，保存文件路径作为标识
        taskHashContent = hashFile;
      }
    }
    // ========== hash 内容读取结束 ==========

    // ========== 新增：多字典模式处理 ==========
    // 自动判断多字典模式：字典数量 >= 2
    const isMultiDictMode = attackMode === 0 && dictionaryPaths.length >= 2;
    
    if (isMultiDictMode) {
        const baseConfig = currentConfig();
        const createdAt = new Date().toISOString();
        const baseName = getDefaultTaskName();
        const groupId = `group-${Date.now()}-${Math.random().toString(16).slice(2)}`;
        
        // 1. 为每个字典创建独立任务
        const newQueueItems: QueueItem[] = [];
        dictionaryPaths.forEach((dictPath, index) => {
            const queueId = `multi-dict-${Date.now()}-${index}-${Math.random().toString(16).slice(2)}`;
            const candidatesResult = calculateCandidates(baseConfig, attackMode, maskEstimate, resources, customResources, userDictionaries, queueId);
    
            const configWithDict: AttackConfig = {
                ...structuredClone(baseConfig),
                dictionaryPath: dictPath,
                dictionaryPaths: undefined,
                candidates: candidatesResult?.candidates,
                isEstimated: candidatesResult?.isEstimated,
                taskName: `${baseName} (${index + 1}/${dictionaryPaths.length})`,    // ← 新增
            };
            
            newQueueItems.push({
                id: queueId,
                name: `${baseName} (${index + 1}/${dictionaryPaths.length})`,
                config: configWithDict,
                status: "pending",
                createdAt,
                candidates: candidatesResult?.candidates,
                isEstimated: candidatesResult?.isEstimated,
                groupId,
                hashContent: taskHashContent,
            });
        });
        
        // 2. 将所有任务加入队列
        setQueueItems((current) => [...current, ...newQueueItems]);
        
        // 3. 清空表单
        clearTaskForm();
        
        // 4. 启动队列（自动执行第一个任务）
        setQueuePaused(false);
        
        // 5. 跳转到队列页面
        setActiveTab("queue");
        setQueueTerminalExpanded(true);
        
        return; // 多字典模式直接返回，不执行后续单字典逻辑
    }
    // ========== 多字典模式处理结束 ==========


    // ========== 新增：攻击序列模式处理 ==========
    const isSequenceMode = attackSequence.length > 0;

    if (isSequenceMode) {
      // 获取全局配置
      const baseConfig = {
        hashMode,
        hashFile,
        hashText,
        taskName: taskName || getDefaultTaskName(),
        optimizedKernel,
        workloadProfile,
        deviceTypes,
        deviceIds,
      };
      
      const createdAt = new Date().toISOString();
      const baseName = baseConfig.taskName;
      
      // 为序列中每个攻击类型创建任务
      const newQueueItems: QueueItem[] = [];

      // 追踪序列项的实际任务数量（用于生成正确的序号）
      let taskCount = 0;
      const totalTasks = attackSequence.reduce((sum, seqItem) => {
        const dictPaths = seqItem.config.dictionaryPaths || [];
        if (seqItem.config.attackMode === 0 && dictPaths.length >= 2) {
          return sum + dictPaths.length;
        }
        return sum + 1;
      }, 0);
      const groupId = `group-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      attackSequence.forEach((seqItem, seqIndex) => {
        const dictPaths = seqItem.config.dictionaryPaths || [];
        const isMultiDict = seqItem.config.attackMode === 0 && dictPaths.length >= 2;

        // 如果是多字典攻击，为每个字典创建独立任务
        if (isMultiDict) {
          dictPaths.forEach((dictPath, dictIndex) => {
            taskCount++;
            const queueId = `multi-seq-${Date.now()}-${seqIndex}-${dictIndex}-${Math.random().toString(16).slice(2)}`;
            
            const configWithSeq: AttackConfig = {
              ...structuredClone(seqItem.config),
              hashMode: baseConfig.hashMode,
              hashFile: baseConfig.hashFile,
              hashText: baseConfig.hashText,
              dictionaryPath: dictPath,
              dictionaryPaths: undefined,  // 单个任务不需要多字典标记
              taskName: `${baseName} (${taskCount}/${totalTasks})`,
            };
            
            const candidatesResult = calculateCandidates(
              configWithSeq,
              seqItem.config.attackMode,
              maskEstimate,
              resources,
              customResources,
              userDictionaries,
              queueId
            );
            
            configWithSeq.candidates = candidatesResult?.candidates;
            configWithSeq.isEstimated = candidatesResult?.isEstimated;
            
            newQueueItems.push({
              id: queueId,
              name: `${baseName} (${taskCount}/${totalTasks})`,
              config: configWithSeq,
              status: "pending",
              createdAt,
              candidates: candidatesResult?.candidates,
              isEstimated: candidatesResult?.isEstimated,
              groupId,
              hashContent: taskHashContent,
            });
          });
        } else {
          // 普通攻击模式，创建单个任务
          taskCount++;
          const queueId = `multi-seq-${Date.now()}-${seqIndex}-${Math.random().toString(16).slice(2)}`;
          
          const configWithSeq: AttackConfig = {
            ...structuredClone(seqItem.config),
            hashMode: baseConfig.hashMode,
            hashFile: baseConfig.hashFile,
            hashText: baseConfig.hashText,
            taskName: `${baseName} (${taskCount}/${totalTasks})`,
          };
          
          const candidatesResult = calculateCandidates(
            configWithSeq,
            seqItem.config.attackMode,
            maskEstimate,
            resources,
            customResources,
            userDictionaries,
            queueId
          );
          
          configWithSeq.candidates = candidatesResult?.candidates;
          configWithSeq.isEstimated = candidatesResult?.isEstimated;
          
          newQueueItems.push({
            id: queueId,
            name: `${baseName} (${taskCount}/${totalTasks})`,
            config: configWithSeq,
            status: "pending",
            createdAt,
            candidates: candidatesResult?.candidates,
            isEstimated: candidatesResult?.isEstimated,
            groupId,
            hashContent: taskHashContent,
          });
        }
      });
      
      // 添加到队列（不立即执行）
      setQueueItems((current) => [...current, ...newQueueItems]);
      
      // 清空序列和表单
      clearAttackSequence();
      clearTaskForm();
      
      // 显示提示
      showToast(queueText(language).added);
      
      return newQueueItems.length > 0 ? newQueueItems[0].id : "";
    }
    // ========== 攻击序列模式处理结束 ==========

    if (shouldConfirmLongTask(maskEstimate)) {
      const confirmed = window.confirm(text.longTaskConfirm
        .replace("{time}", formatDuration(maskEstimate?.estimatedSeconds ?? 0))
        .replace("{candidates}", maskEstimate?.candidates ? formatBigInt(maskEstimate.candidates) : "-"));
      if (!confirmed) return;
    }
    
    const config = currentConfig();
    const createdAt = new Date().toISOString();
    const name = getDefaultTaskName();
    const queueId = `queue-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    
    const candidatesResult = calculateCandidates(config, attackMode, maskEstimate, resources, customResources, userDictionaries, queueId);
    config.candidates = candidatesResult?.candidates;
    config.isEstimated = candidatesResult?.isEstimated;

    // 先将任务加入队列
    setQueueItems((current) => [
      ...current,
      {
        id: queueId,
        name,
        config: structuredClone(config),
        status: "pending" as QueueStatus,
        createdAt,
        candidates: candidatesResult?.candidates,
        isEstimated: candidatesResult?.isEstimated,
        hashContent: taskHashContent,
      },
    ]);
    
    try {
      // 将 bigint 转换为字符串以便正确序列化
      const configForBackend = {
        ...config,
        candidates: typeof config.candidates === 'string'
          ? parseInt(config.candidates, 10)
          : typeof config.candidates === 'bigint'
            ? Number(config.candidates)
            : config.candidates,
      };
      // 使用原始逻辑调用后端
      const response = await invoke<StartResponse>("start_attack", { config: configForBackend });
      
      // 更新队列任务状态
      setQueueItems((current) => current.map((item) => 
        item.id === queueId ? { 
          ...item, 
          status: "running" as QueueStatus, 
          startedAt: new Date().toISOString(),
          taskId: response.taskId 
        } : item
      ));
      
      // 更新状态
      setTaskId(response.taskId);
      setSelectedTaskId(response.taskId);
      setBackendCommand(response.commandPreview);
      setRunning(true);
      
      // 清空任务页面
      clearTaskForm();
      
      // 跳转到队列页面
      setActiveTab("queue");
      setQueueTerminalExpanded(true);
      
      await refreshTasks();
    } catch (err) {
      // 使用原始错误处理逻辑
      setError(String(err));
      
      // 更新队列任务状态为失败
      setQueueItems((current) => current.map((item) => 
        item.id === queueId ? { 
          ...item, 
          status: "failed" as QueueStatus, 
          finishedAt: new Date().toISOString(),
          error: String(err) 
        } : item
      ));
    }
  }

  async function stopAttack() {
    if (!taskId || stopping) return;
    setStopping(true);
    // 在发送停止请求前，先将队列中的任务状态设置为 stopped
    setQueueItems((current) => current.map((item) => {
      if (item.taskId === taskId && item.status === "running") {
        return { ...item, status: "stopped" as QueueStatus, finishedAt: new Date().toISOString() };
      }
      return item;
    }));
    try {
      await invoke("stop_attack", { taskId });
      showToast(text.stopRequested);
    } catch (err) {
      setError(String(err));
      setStopping(false);
    }
  }

  async function rerunTask(id: string) {
    try {
      const response = await invoke<StartResponse>("rerun_task", { taskId: id });
      setTaskId(response.taskId);
      setSelectedTaskId(response.taskId);
      setBackendCommand(response.commandPreview);
      setRunning(true);
      setActiveTab("queue");  // 改为跳转到队列页面
      setQueueTerminalExpanded(true);  // 展开实时终端
      await refreshTasks();
    } catch (err) {
      setError(String(err));
    }
  }

  async function restoreTask(id: string) {
    try {
      const response = await invoke<StartResponse>("restore_attack", { taskId: id });
      setTaskId(response.taskId);
      setSelectedTaskId(response.taskId);
      setBackendCommand(response.commandPreview);
      setRunning(true);
      setActiveTab("queue");  // 改为跳转到队列页面
      setQueueTerminalExpanded(true);  // 展开实时终端
      await refreshTasks();
    } catch (err) {
      setError(String(err));
    }
  }

  async function deleteTask(id: string) {
    if (!window.confirm(text.deleteConfirm)) return;
    try {
      const next = await invoke<TaskManifest[]>("delete_task", { taskId: id });
      
      // 先清理名称映射，再更新任务列表
      deleteTaskName(id);

      // 清理 candidates 数据
      try {
        const savedCandidates: Record<string, { candidates: string; isEstimated: boolean }> = JSON.parse(
          localStorage.getItem(TASK_CANDIDATES_STORAGE_KEY) || "{}"
        );
        delete savedCandidates[id];
        localStorage.setItem(TASK_CANDIDATES_STORAGE_KEY, JSON.stringify(savedCandidates));
      } catch (e) {
        console.error("Failed to delete candidates:", e);
      }
      
      // 清理提取的密码
      deleteExtractedPasswords(id);
      
      // 清理队列中与已删除任务相关的项
      setQueueItems(current => current.filter(item => item.taskId !== id));
      
      // 加载保存的任务名称映射并应用到新任务列表
      const savedNames = loadTaskNames();
      // 加载保存的 candidates 和 isEstimated 值
      let savedCandidates: Record<string, { candidates: string; isEstimated: boolean }> = {};
      try {
        savedCandidates = JSON.parse(localStorage.getItem(TASK_CANDIDATES_STORAGE_KEY) || "{}");
      } catch (e) {
        console.error("Failed to load saved candidates:", e);
      }

      // 合并数据：添加 extractedPasswords 和其他必要字段
      const tasksWithNames = next.map(task => {
        const saved = savedCandidates[task.taskId];
        const existingPasswords = loadExtractedPasswords(task.taskId);
        
        // 关键修复：将 candidates 值转换为字符串并检查是否有效
        const candidateStr = String(saved?.candidates ?? "").trim();
        const isValidCandidates = candidateStr !== "" && 
          candidateStr !== "null" && 
          candidateStr !== "undefined";
        
        const taskWithCandidates = isValidCandidates ? {
          ...task,
          config: {
            ...task.config,
            candidates: BigInt(candidateStr),  // 使用验证后的字符串
            isEstimated: saved.isEstimated,
          },
        } : task;
        
        return {
          ...taskWithCandidates,
          taskName: savedNames[task.taskId] || task.taskName,
          extractedPasswords: existingPasswords,
          passwordsExtracted: existingPasswords !== null,
        };
      });

      // 更新任务列表和选中状态
      setTasks(tasksWithNames);
      const nextSelectedId = next[0]?.taskId ?? "";
      setSelectedTaskId(nextSelectedId);
      setResults(null);
      setResultsTaskId("");
      setTaskLog(null);
      setTaskLogTaskId("");
      
      if (nextSelectedId) await Promise.all([readResultsFor(nextSelectedId), readTaskLogFor(nextSelectedId)]);
    } catch (err) {
      setError(String(err));
    }
  }

  async function readResultsFor(id = selectedTaskId) {
    if (!id) return;
    try {
      setResults(null);
      setResultsTaskId(id);
      // 直接读取结果，不再重复设置 selectedTaskId
      setResults(await invoke<ResultsResponse>("read_results", { taskId: id }));
    } catch (err) {
      setError(String(err));
    }
  }

  async function readTaskLogFor(id = selectedTaskId) {
    if (!id) return;
    try {
      setTaskLog(null);
      setTaskLogTaskId(id);
      setTaskLog(await invoke<ResultsResponse>("read_task_log", { taskId: id }));
      setSelectedTaskId(id);
    } catch (err) {
      setError(String(err));
    }
  }

  async function analyzeLog(id = selectedTaskId) {
    if (!id) return;
    setAiTaskId(id);
    setAiTextByTask((current) => ({ ...current, [id]: "" }));
    setAiErrorByTask((current) => ({ ...current, [id]: "" }));
    setAiRunningTaskIds((current) => (current.includes(id) ? current : [...current, id]));
    setAiOpen(true);
    setAiMinimized(false);
    try {
      await invoke("start_ai_log_analysis", { taskId: id });
    } catch (err) {
      setAiErrorByTask((current) => ({ ...current, [id]: String(err) }));
      setAiRunningTaskIds((current) => current.filter((taskId) => taskId !== id));
    }
  }

  async function startHelpAi(config: AiHashConsultConfig) {
    const localId = `help-ai-${Date.now()}`;
    setAiTaskId(localId);
    setAiTextByTask((current) => ({ ...current, [localId]: "" }));
    setAiErrorByTask((current) => ({ ...current, [localId]: "" }));
    setAiRunningTaskIds((current) => (current.includes(localId) ? current : [...current, localId]));
    setAiOpen(true);
    setAiMinimized(false);
    try {
      const backendId = await invoke<string>("start_ai_hash_consult", { config });
      setAiTaskId(backendId);
      setAiTextByTask((current) => ({ ...current, [backendId]: current[localId] ?? "" }));
      setAiErrorByTask((current) => ({ ...current, [backendId]: current[localId] ?? "" }));
      setAiRunningTaskIds((current) => [...current.filter((id) => id !== localId), backendId]);
    } catch (err) {
      setAiErrorByTask((current) => ({ ...current, [localId]: String(err) }));
      setAiRunningTaskIds((current) => current.filter((id) => id !== localId));
    }
  }

  async function copyResults() {
    if (!selectedResults?.content) return;
    await writeText(selectedResults.content);
    showToast(text.resultsCopied);
  }

  async function exportResults() {
    if (!selectedTaskId) return;
    const destination = await save({ defaultPath: `${selectedTaskId}-cracked.txt` });
    if (typeof destination !== "string") return;
    try {
      await invoke("export_results", { taskId: selectedTaskId, destination });
      showToast(text.resultsExported);
    } catch (err) {
      setError(String(err));
    }
  }

  async function openTaskDir() {
    if (!selectedTaskId) return;
    try {
      await invoke("open_task_dir", { taskId: selectedTaskId });
    } catch (err) {
      setError(String(err));
    }
  }

  // 检查路径是否在软件数据目录中
  function isInAppDataDirectory(path: string | null | undefined): boolean {
    if (!path) return false;
    
    // 检查是否在应用数据目录中（包含 imported-presets）
    const appDataPatterns = [
      "AppData\\Roaming\\com.hashcatgui.app",
      "/AppData/Roaming/com.hashcatgui.app",
      "custom-resource",     // 新增：自定义资源目录
      "imported-presets",    // 导入预设目录
      "imported-resource",   // 新增：导入资源目录
    ];
    
    return appDataPatterns.some(pattern => path.includes(pattern));
  }

  async function deleteCustomResource(resource: CustomResource) {
    const resourcePath = resource.path;
    
    // 1. 在删除前计算需要清理的文件（排除当前资源）
    const shouldDeleteFile = resourcePath && 
                            isInAppDataDirectory(resourcePath) && 
                            !isPathReferencedExcludingResource(resourcePath, resource.id);
    
    // 2. 删除资源并立即保存
    const updatedResources = customResources.filter((item) => item.id !== resource.id);
    setCustomResources(updatedResources);
    
    // 立即保存到文件（不依赖 useEffect）
    try {
      await invoke("write_custom_resources_file", { resourcesJson: JSON.stringify(updatedResources) });
    } catch (error) {
      console.error('Failed to save custom resources after delete:', error);
    }
    
    // 3. 清理文件（如果未被其他资源/预设引用）
    if (shouldDeleteFile) {
      try {
        await invoke("delete_custom_resource_file", { path: resourcePath });
      } catch {
        // 文件删除失败，忽略
      }
    }
  }

  // 新增：检查路径是否被其他资源（排除指定资源）或预设引用
  function isPathReferencedExcludingResource(path: string, excludeResourceId: string): boolean {
    // 1. 检查是否被其他自定义资源引用（排除当前资源）
    const referencedByResource = customResources.some(
      (r) => r.id !== excludeResourceId && r.path === path
    );
    
    // 2. 检查是否被预设引用
    const referencedByPreset = presets.some((preset) => {
      const paths: (string | undefined)[] = [
        preset.dictionaryPath,
        preset.dictionaryPath2,
        ...(preset.dictionaryPaths || []),
        preset.maskPath,
        ...(preset.rulePaths || []),
      ];
      return paths.some((p) => p === path);
    });
    
    return referencedByResource || referencedByPreset;
  }

  function loadTask(task: TaskManifest) {
    setTaskName(task.taskName);
    setHashMode(task.config.hashMode);
    setAttackMode(task.config.attackMode);
    setHashText(task.config.hashText ?? "");
    setHashFile(task.config.hashFile ?? "");
    setDictionaryPath(task.config.dictionaryPath ?? "");
    setDictionaryPaths(task.config.dictionaryPaths ?? []);
    setMask(task.config.mask ?? "");
    setMaskFile(task.config.maskFile ?? "");
    setTemplatePrefixMask(task.config.templatePrefixMask ?? "");
    setTemplateSuffixMask(task.config.templateSuffixMask ?? "");
    setIncrement(Boolean(task.config.increment));
    setIncrementMin(task.config.incrementMin ? String(task.config.incrementMin) : "");
    setIncrementMax(task.config.incrementMax ? String(task.config.incrementMax) : "");
    setCustomCharset1(task.config.customCharset1 ?? "");
    setCustomCharset2(task.config.customCharset2 ?? "");
    setCustomCharset3(task.config.customCharset3 ?? "");
    setCustomCharset4(task.config.customCharset4 ?? "");
    setRulePaths(task.config.rulePaths ?? []);
    setOptimizedKernel(Boolean(task.config.optimizedKernel));
    setWorkloadProfile(task.config.workloadProfile ?? 3);
    setDeviceTypes(task.config.deviceTypes?.length ? task.config.deviceTypes : ["2"]);
    setDeviceIds(task.config.deviceIds ?? "");
    setActiveTab("config");
  }

  // 生成格式化的时间戳字符串，格式：YYYY-MM-DDTHH-mm-ss
  const formatTimestamp = (date: Date) => {
    const pad = (n: number) => n.toString().padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}-${pad(date.getMinutes())}-${pad(date.getSeconds())}`;
  };

  // 获取默认任务名称
  const getDefaultTaskName = () => {
    if (taskName.trim()) {
      return taskName.trim();
    }
    
    const isHc22000 = hashFile.trim().toLowerCase().endsWith(".hc22000");
    
    // 单行解析成功，或单选模式下选中一行时，使用 ESSID_BSSID 格式
    if (isHc22000 && hc22000Info) {
      // 单选模式下选中一行
      if (hc22000SelectionMode === 'single' && selectedHc22000Indices.length === 1) {
        const entry = hc22000Info.entries[selectedHc22000Indices[0]];
        const unsafeChars = /[\\/:*?"<>|]/g;
        const safeEssid = entry.essid.replace(unsafeChars, '_');
        const safeBssid = entry.bssid.replace(/:/g, '-');
        return `${safeEssid}_${safeBssid}`;
      }
      // 只有单行且解析成功时使用 ESSID_BSSID 格式
      if (hc22000Info.entries.length === 1) {
        const entry = hc22000Info.entries[0];
        const unsafeChars = /[\\/:*?"<>|]/g;
        const safeEssid = entry.essid.replace(unsafeChars, '_');
        const safeBssid = entry.bssid.replace(/:/g, '-');
        return `${safeEssid}_${safeBssid}`;
      }
    }

    if (hashFile.trim()) {
      // 如果有原始文件路径（说明是从 cap/pcap 转换来的），且转换后的文件包含多行，则使用原始文件名
      if (originalHashFile && hc22000Info && hc22000Info.lineCount > 1) {
        const fileName = originalHashFile.split(/[\\/]/).pop() || '';
        return fileName;
      }
      const fileName = hashFile.split(/[\\/]/).pop() || '';
      return fileName;
    }
    
    if (hashText.trim()) {
      return 'Hashcat task';
    }
    
    return `Task_${formatTimestamp(new Date())}`;
  };

  function currentConfig(): AttackConfig {
    const configTaskName = getDefaultTaskName();
    return {
      taskName: configTaskName,
      attackMode,
      dictionaryPath,
      dictionaryPath2,
      dictionaryPaths: dictionaryPaths.length > 0 ? dictionaryPaths : undefined,
      useRules: useRules || undefined,
      useLeftRule: useLeftRule || undefined,
      useRightRule: useRightRule || undefined,
      leftRule: (attackMode === 0 ? useRules : useLeftRule) ? leftRule : undefined,       // 只有勾选时才包含
      rightRule: useRightRule ? rightRule : undefined,    // 只有勾选时才包含
      hashFile,
      hashMode,
      hashText,
      mask,
      maskFile,
      templatePrefixMask,
      templateSuffixMask,
      increment,
      incrementMin: numberOrNull(incrementMin),
      incrementMax: numberOrNull(incrementMax),
      customCharset1: charsetEnabled ? customCharset1 : "",
      customCharset2: charsetEnabled ? customCharset2 : "",
      customCharset3: charsetEnabled ? customCharset3 : "",
      customCharset4: charsetEnabled ? customCharset4 : "",
      charsetFile1: charsetEnabled ? charsetFile1 : "",
      charsetFile2: charsetEnabled ? charsetFile2 : "",
      charsetFile3: charsetEnabled ? charsetFile3 : "",
      charsetFile4: charsetEnabled ? charsetFile4 : "",
      optimizedKernel,
      rulePaths: useRules ? rulePaths : [],
      workloadProfile,
      deviceTypes,
      deviceIds,
    };
  }

  // 估算字典候选数量
  async function estimateDictionaryCandidates(queueId: string, dictPath1: string, dictPath2?: string | null) {
    try {
      // 使用新的后端函数 count_file_lines，返回 { count, isEstimated }
      const result1 = await invoke<{ count: number; isEstimated: boolean }>("count_file_lines", { path: dictPath1 });

      let total = BigInt(result1.count);
      let isEstimated = result1.isEstimated;

      if (dictPath2) {
        const result2 = await invoke<{ count: number; isEstimated: boolean }>("count_file_lines", { path: dictPath2 });
        total = BigInt(result1.count) * BigInt(result2.count);
        isEstimated = isEstimated || result2.isEstimated; // 只要有一个是估算，整体就是估算
      }

      // 更新队列中任务的候选数量
      setQueueItems((current) => {
        const updated = current.map((item) => {
          if (item.id === queueId) {
            return { ...item, candidates: total, isEstimated };
          }
          return item;
        });
        return updated;
      });

      // 新增：更新攻击序列
      setAttackSequence((current) => {
        return current.map((item) => {
          if (item.id === queueId) {
            return { ...item, candidates: total, isEstimated };
          }
          return item;
        });
      });
    } catch (err) {
      console.error(err);
    }
  }

  // 估算字典+规则的候选数量
  async function estimateDictWithRuleCandidates(
    queueId: string, 
    dictPath: string, 
    rulePaths?: string[]
  ) {
    try {
      // 先计算字典行数
      const dictResult = await invoke<LineCountResult>("count_file_lines", { path: dictPath });
      let totalCandidates = BigInt(dictResult.count);
      let isEstimated = dictResult.is_estimated;

      // 如果有规则文件，计算规则行数（将所有规则文件行数相乘）
      if (rulePaths && rulePaths.length > 0) {
        let totalRuleLines = BigInt(1);
        for (const rulePath of rulePaths) {
          const ruleResult = await invoke<LineCountResult>("count_rule_file_lines", { path: rulePath });
          totalRuleLines *= BigInt(ruleResult.count);
          if (ruleResult.is_estimated) {
            isEstimated = true;
          }
        }
        totalCandidates *= totalRuleLines;
      }

      // 更新队列项
      setQueueItems(prev => prev.map(item => 
        item.id === queueId 
          ? { ...item, candidates: totalCandidates, isEstimated }
          : item
      ));

      // 更新预设（如果适用）
      setPresets(prev => prev.map(p => 
        p.id === queueId 
          ? { ...p, candidates: totalCandidates.toString(), isEstimated }
          : p
      ));

      // 更新攻击序列
      setAttackSequence((current) => {
        return current.map((item) => {
          if (item.id === queueId) {
            return { ...item, candidates: totalCandidates, isEstimated };
          }
          return item;
        });
      });
    } catch (err) {
      console.error("Failed to estimate candidates with rules:", err);
    }
  }

  // 估算混合模式候选数量（字典+掩码 或 掩码+字典）
  async function estimateHybridCandidates(queueId: string, dictPath: string, maskCandidates: bigint) {
    try {
      // 计算字典行数
      const result = await invoke<{ count: number; isEstimated: boolean }>("count_file_lines", { path: dictPath });
      
      // 混合模式候选数 = 字典行数 × 掩码候选数
      const total = BigInt(result.count) * maskCandidates;

      // 更新队列中任务的候选数量
      setQueueItems((current) => {
        const updated = current.map((item) => {
          if (item.id === queueId) {
            return { ...item, candidates: total, isEstimated: result.isEstimated };
          }
          return item;
        });
        return updated;
      });

      // 新增：更新攻击序列
      setAttackSequence((current) => {
        return current.map((item) => {
          if (item.id === queueId) {
            return { ...item, candidates: total, isEstimated: result.isEstimated };
          }
          return item;
        });
      });
    } catch (err) {
      console.error(err);
    }
  }

  // 估算掩码文件的候选数量
  async function estimateMaskFileCandidates(
    queueId: string,
    maskFilePath: string,
    increment?: boolean | null,
    incrementMin?: string | number | null,
    incrementMax?: string | number | null
  ) {
    try {
      let total: number;
      if (increment) {
        // 启用递增
        const minValue = typeof incrementMin === "string" ? parseInt(incrementMin, 10) : incrementMin;
        const maxValue = typeof incrementMax === "string" ? parseInt(incrementMax, 10) : incrementMax;
        
        const min = (minValue === null || minValue === undefined || Number.isNaN(minValue)) ? 1 : minValue;
        const max = (maxValue === null || maxValue === undefined || Number.isNaN(maxValue)) ? 0 : maxValue;  // 0 表示使用掩码长度
        
        total = await invoke<number>("count_mask_file_candidates_with_increment", {
          path: maskFilePath,
          enableIncrement: true,
          incrementMin: min,
          incrementMax: max,
        });
      } else {
        // 不启用递增
        total = await invoke<number>("count_mask_file_candidates_with_increment", {
          path: maskFilePath,
          enableIncrement: false,
          incrementMin: 1,
          incrementMax: 0,
        });
      }
      
      setQueueItems((current) => {
        const updated = current.map((item) => {
          if (item.id === queueId) {
            return { ...item, candidates: BigInt(total) };
          }
          return item;
        });
        return updated;
      });

      // 新增：更新攻击序列
      setAttackSequence((current) => {
        return current.map((item) => {
          if (item.id === queueId) {
            return { ...item, candidates: BigInt(total), isEstimated: false };
          }
          return item;
        });
      });
    } catch (err) {
      console.error(err);
    }
  }

  // 估算使用字符集文件的掩码候选数量
  async function estimateCharsetFileCandidates(queueId: string, mask: string, charsetFiles: string[]) {
    try {
      // 先获取每个字符集文件的字符数
      const charsetSizes: number[] = [];
      for (let i = 0; i < charsetFiles.length; i++) {
        const filePath = charsetFiles[i];
        if (filePath) {
          const count = await invoke<number>("count_charset_file_chars", { path: filePath });
          charsetSizes[i] = count;
        } else {
          charsetSizes[i] = 0;
        }
      }
      
      // 根据掩码计算候选数量
      let total = 1n;
      const sizes: Record<string, bigint> = {
        l: 26n,  // 小写字母
        u: 26n,  // 大写字母
        d: 10n,  // 数字
        h: 16n,  // 小写十六进制
        H: 16n,  // 大写十六进制
        s: 33n,  // 特殊字符
        a: 95n,  // 可打印ASCII
        b: 256n, // 所有字节
      };
      
      for (let index = 0; index < mask.length; index++) {
        const char = mask[index];
        if (char !== "?") continue;
        const token = mask[index + 1];
        if (!token) continue;
        if (token === "?") {
          index++;
          continue;
        }
        
        let size: bigint;
        const slot = Number(token);
        if (slot >= 1 && slot <= 4 && charsetSizes[slot - 1] > 0) {
          // 使用字符集文件的字符数
          size = BigInt(charsetSizes[slot - 1]);
        } else {
          // 使用内置字符集大小
          size = sizes[token] || 0n;
        }
        
        if (size === 0n) return;
        total *= size;
        index++;
      }
      
      setQueueItems((current) => {
        const updated = current.map((item) => {
          if (item.id === queueId) {
            return { ...item, candidates: total };
          }
          return item;
        });
        return updated;
      });

      // 新增：更新攻击序列
      setAttackSequence((current) => {
        return current.map((item) => {
          if (item.id === queueId) {
            return { ...item, candidates: total, isEstimated: false };
          }
          return item;
        });
      });
    } catch (err) {
      console.error(err);
    }
  }

  function calculateCandidates(
    config: AttackConfig,
    attackMode: number,
    maskEstimate: MaskEstimate | null,
    resources: ResourceInfo[],
    customResources: CustomResource[],
    userDictionaries: UserDictionary[],
    queueId: string
  ): { candidates: bigint; isEstimated?: boolean } | undefined {
    if (attackMode === 3 && config.mask) {
      // 检查是否使用了字符集文件
      const hasCharsetFiles = 
        config.charsetFile1 || config.charsetFile2 || config.charsetFile3 || config.charsetFile4;
      
      if (hasCharsetFiles) {
        // 使用字符集文件：需要异步计算
        const charsetFiles = [
          config.charsetFile1 || "",
          config.charsetFile2 || "",
          config.charsetFile3 || "",
          config.charsetFile4 || ""
        ];
        void estimateCharsetFileCandidates(queueId, config.mask, charsetFiles);
        return undefined;
      }
      // 没有使用字符集文件：使用现有的估算
      if (maskEstimate?.candidates) {
        return { candidates: maskEstimate.candidates };
      }
    } else if (attackMode === 3 && config.maskFile) {
      // 掩码模式（使用掩码文件）：异步计算掩码文件的候选数量
      void estimateMaskFileCandidates(
        queueId,
        config.maskFile,
        config.increment,
        config.incrementMin,
        config.incrementMax
      );
      return undefined;
    } else if ((attackMode === 0 || attackMode === 1) && config.dictionaryPath) {
      // 字典模式：尝试从资源信息中获取预计算的候选数量
      let dictCandidates: number | undefined;
      
      // 先从内置资源中查找
      const builtinResource = resources.find(r => r.kind === "dictionary" && r.path === config.dictionaryPath);
      if (builtinResource?.candidates) {
        dictCandidates = builtinResource.candidates;
        return { candidates: BigInt(dictCandidates), isEstimated: builtinResource.isEstimated || false };
      }
      
      // 如果在内置资源中找不到，尝试在用户字典中查找
      if (dictCandidates === undefined) {
        const userDict = userDictionaries.find(d => d.path === config.dictionaryPath);
        if (userDict?.candidates) {
          dictCandidates = userDict.candidates;
          return { candidates: BigInt(dictCandidates), isEstimated: userDict.isEstimated || false };
        }
      }

      // 如果还找不到，尝试在自定义资源中查找
      if (dictCandidates === undefined) {
        const customResource = customResources.find(r => r.type === "dictionary" && r.path === config.dictionaryPath);
        const customCandidates = (customResource as any)?.candidates;
        if (customCandidates !== undefined && customCandidates !== null) {
          return { candidates: BigInt(customCandidates), isEstimated: (customResource as any).isEstimated || false };
        }
      }

      if (dictCandidates !== undefined) {
        // 检查是否启用规则且有规则文件
        const useRulesConfig = config as unknown as { useRules?: boolean };
        if (useRulesConfig.useRules && config.rulePaths && config.rulePaths.length > 0) {
          void estimateDictWithRuleCandidates(queueId, config.dictionaryPath, config.rulePaths);
          return undefined;
        }
        return { candidates: BigInt(dictCandidates), isEstimated: false };
      } else {
        // 如果没有预计算，异步计算候选数量
        const useRulesConfig = config as unknown as { useRules?: boolean };
        if (useRulesConfig.useRules && config.rulePaths && config.rulePaths.length > 0) {
          void estimateDictWithRuleCandidates(queueId, config.dictionaryPath, config.rulePaths);
        } else {
          void estimateDictionaryCandidates(queueId, config.dictionaryPath, config.dictionaryPath2);
        }
        return undefined;
      }
    } else if ((attackMode === 6 || attackMode === 7) && config.dictionaryPath && maskEstimate?.candidates) {
      // 混合模式（字典+掩码 / 掩码+字典）：字典行数 × 掩码候选数
      void estimateHybridCandidates(queueId, config.dictionaryPath, maskEstimate.candidates);
      return undefined;
    } else if (attackMode === 9 && config.dictionaryPath && maskEstimate?.candidates) {
      // 模板攻击模式：字典行数 × 前缀掩码候选数 × 后缀掩码候选数
      void estimateHybridCandidates(queueId, config.dictionaryPath, maskEstimate.candidates);
      return undefined;
    }
    
    return undefined;
  }

  function isValidConfig(requireHash: boolean = true): { valid: boolean; error?: string } {
    return validateAttackConfig({
      attackMode,
      hashMode,
      hashText,
      hashFile,
      dictionaryPath,
      dictionaryPath2,
      dictionaryPaths,
      mask,
      maskFile,
      templatePrefixMask,
      templateSuffixMask,
      requireHash,  // 使用参数值
    }, text);
  }

  function clearTaskForm() {
    setHashMode("0");           // 重置 Hash 模式为默认值
    setHashFile("");            // 清空 Hash 文件路径
    setHashText("");            // 清空 Hash 文本	
    setTaskName("");            // 清空任务名称
    setOriginalHashFile("");    // 清空原始文件路径（新增）
    setHc22000Info(null);       // 清空 WPA 解析信息（新增）
    setSelectedHc22000Indices([]);  // 清空选中的 hc22000 条目（新增）
    setHc22000SelectionMode('multi'); // 恢复多选模式（新增）
    clearAttackConfig();
  }

  async function addCurrentTaskToQueue(): Promise<string> {
    if (!hashFile && !hashText) {
      setError(text.missingHash);
      return "";
    }

    // ========== 新增：读取并保存 hash 内容 ==========
    let taskHashContent = "";
    if (hashText?.trim()) {
      taskHashContent = normalizeHashContent(hashText);
    } else if (hashFile) {
      try {
        const response = await invoke<FilePreviewResponse>("preview_text_file", {
          path: hashFile,
          allowFull: true
        });
        taskHashContent = normalizeHashContent(response.content);
      } catch {
        // 如果读取失败，保存文件路径作为标识
        taskHashContent = hashFile;
      }
    }
    // ========== hash 内容读取结束 ==========

    const hasSequence  = attackSequence.length > 0;
    if (!hasSequence) {
      const configResult = isValidConfig();
      if (!configResult.valid) {
        // 校验失败，显示错误提示
        if (configResult.error) {
          setError(configResult.error);
        }
        return "";
      }
    }

    // 提取所有文件路径
    const filePaths = extractFilePaths(currentConfig());
    
    // 检查文件是否存在
    const missingFiles = await checkFilesExist(filePaths);
    
    // 如果有文件不存在，显示错误提示
    if (missingFiles.length > 0) {
      const errorMsg = language === "zh" 
        ? `以下文件不存在：\n${missingFiles.join('\n')}`
        : `The following files do not exist:\n${missingFiles.join('\n')}`;
      setError(errorMsg);
      return "";
    }
    
    setError("");
    // ========== 新增：多字典模式处理 ==========
    // 自动判断多字典模式：字典数量 >= 2
    const isMultiDictMode = attackMode === 0 && dictionaryPaths.length >= 2;
    
    if (isMultiDictMode) {
      const baseConfig = currentConfig();
      const createdAt = new Date().toISOString();
      const baseName = getDefaultTaskName();
      const groupId = `group-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      
      // 1. 为每个字典创建独立任务
      const newQueueItems: QueueItem[] = [];
      dictionaryPaths.forEach((dictPath, index) => {
          const queueId = `multi-dict-${Date.now()}-${index}-${Math.random().toString(16).slice(2)}`;
          const configWithDict: AttackConfig = {
              ...structuredClone(baseConfig),
              dictionaryPath: dictPath,       // 使用当前字典
              dictionaryPaths: undefined,     // 单个任务不需要多字典标记
              taskName: `${baseName} (${index + 1}/${dictionaryPaths.length})`,
            };
          
          const candidatesResult = calculateCandidates(configWithDict, attackMode, maskEstimate, resources, customResources, userDictionaries, queueId);
    
          newQueueItems.push({
              id: queueId,
              name: `${baseName} (${index + 1}/${dictionaryPaths.length})`,
              config: configWithDict,
              status: "pending",
              createdAt,
              candidates: candidatesResult?.candidates,      // 新增
              isEstimated: candidatesResult?.isEstimated,    // 新增
              groupId,
              hashContent: taskHashContent,
          });
      });
      
      // 2. 将所有任务加入队列（不立即执行）
      setQueueItems((current) => [...current, ...newQueueItems]);
      
      // 3. 清空表单
      clearTaskForm();
      
      // 4. 显示提示
      showToast(queueText(language).added);
      
      return newQueueItems[0]?.id || ""; // 返回第一个任务ID
    }
    // ========== 多字典模式处理结束 ==========
    

    // ========== 新增：攻击序列模式处理 ==========
    const isSequenceMode = attackSequence.length > 0;

    if (isSequenceMode) {
      // 获取全局配置（hash 设置和任务设置）
      const baseConfig = {
        hashMode,
        hashFile,
        hashText,
        taskName: taskName || getDefaultTaskName(),
        optimizedKernel,
        workloadProfile,
        deviceTypes,
        deviceIds,
      };
      
      const createdAt = new Date().toISOString();
      const baseName = baseConfig.taskName;
      
      // 为序列中每个攻击类型创建任务
      const newQueueItems: QueueItem[] = [];

      // 追踪序列项的实际任务数量（用于生成正确的序号）
      let taskCount = 0;
      const totalTasks = attackSequence.reduce((sum, seqItem) => {
        const dictPaths = seqItem.config.dictionaryPaths || [];
        if (seqItem.config.attackMode === 0 && dictPaths.length >= 2) {
          return sum + dictPaths.length;
        }
        return sum + 1;
      }, 0);
      const groupId = `group-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      attackSequence.forEach((seqItem, seqIndex) => {
        const dictPaths = seqItem.config.dictionaryPaths || [];
        const isMultiDict = seqItem.config.attackMode === 0 && dictPaths.length >= 2;

        // 如果是多字典攻击，为每个字典创建独立任务
        if (isMultiDict) {
          dictPaths.forEach((dictPath, dictIndex) => {
            taskCount++;
            const queueId = `multi-seq-${Date.now()}-${seqIndex}-${dictIndex}-${Math.random().toString(16).slice(2)}`;
            
            const configWithSeq: AttackConfig = {
              ...structuredClone(seqItem.config),
              hashMode: baseConfig.hashMode,
              hashFile: baseConfig.hashFile,
              hashText: baseConfig.hashText,
              dictionaryPath: dictPath,
              dictionaryPaths: undefined,  // 单个任务不需要多字典标记
              taskName: `${baseName} (${taskCount}/${totalTasks})`,
            };
            
            const candidatesResult = calculateCandidates(
              configWithSeq,
              seqItem.config.attackMode,
              maskEstimate,
              resources,
              customResources,
              userDictionaries,
              queueId
            );
            
            configWithSeq.candidates = candidatesResult?.candidates;
            configWithSeq.isEstimated = candidatesResult?.isEstimated;
            
            newQueueItems.push({
              id: queueId,
              name: `${baseName} (${taskCount}/${totalTasks})`,
              config: configWithSeq,
              status: "pending",
              createdAt,
              candidates: candidatesResult?.candidates,
              isEstimated: candidatesResult?.isEstimated,
              groupId,
              hashContent: taskHashContent,
            });
          });
        } else {
          // 普通攻击模式，创建单个任务
          taskCount++;
          const queueId = `multi-seq-${Date.now()}-${seqIndex}-${Math.random().toString(16).slice(2)}`;
          
          const configWithSeq: AttackConfig = {
            ...structuredClone(seqItem.config),
            hashMode: baseConfig.hashMode,
            hashFile: baseConfig.hashFile,
            hashText: baseConfig.hashText,
            taskName: `${baseName} (${taskCount}/${totalTasks})`,
          };
          
          const candidatesResult = calculateCandidates(
            configWithSeq,
            seqItem.config.attackMode,
            maskEstimate,
            resources,
            customResources,
            userDictionaries,
            queueId
          );
          
          configWithSeq.candidates = candidatesResult?.candidates;
          configWithSeq.isEstimated = candidatesResult?.isEstimated;
          
          newQueueItems.push({
            id: queueId,
            name: `${baseName} (${taskCount}/${totalTasks})`,
            config: configWithSeq,
            status: "pending",
            createdAt,
            candidates: candidatesResult?.candidates,
            isEstimated: candidatesResult?.isEstimated,
            groupId,
            hashContent: taskHashContent,
          });
        }
      });
      
      // 添加到队列
      setQueueItems((current) => [...current, ...newQueueItems]);
      
      // 清空序列和表单
      clearAttackSequence();
      clearTaskForm();
      
      showToast(queueText(language).added);
      
      return newQueueItems.length > 0 ? newQueueItems[0].id : "";
    }
    // ========== 攻击序列模式处理结束 ==========

    const config = currentConfig();
    const createdAt = new Date().toISOString();
    const name = getDefaultTaskName();
    const queueId = `queue-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    
    // 计算候选数量
    const candidatesResult = calculateCandidates(config, attackMode, maskEstimate, resources, customResources, userDictionaries, queueId);
    config.candidates = candidatesResult?.candidates;
    config.isEstimated = candidatesResult?.isEstimated;

    setQueueItems((current) => [
      ...current,
      {
        id: queueId,
        name,
        config: structuredClone(config),
        status: "pending" as QueueStatus,
        createdAt,
        candidates: candidatesResult?.candidates,
        isEstimated: candidatesResult?.isEstimated,
        hashContent: taskHashContent,
      },
    ]);
    
    clearTaskForm();
    
    showToast(queueText(language).added);
    
    return queueId;  // 返回任务 ID
  }

  // 加入攻击序列
  function addToAttackSequence(): boolean {
    // 使用 isValidConfig(false) 不校验 hash
    const configResult = isValidConfig(false);
    if (!configResult.valid) {
      if (configResult.error) {
        setError(configResult.error);
      }
      return false;
    }
    setError("");
    
    // 获取当前配置
    const config = currentConfig();
    // 生成唯一 ID
    const sequenceId = `seq-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    
    // 计算候选数量
    const candidatesResult = calculateCandidates(
      config, 
      attackMode, 
      maskEstimate, 
      resources, 
      customResources, 
      userDictionaries, 
      sequenceId
    );
    
    // 创建序列项
    const newItem: AttackSequenceItem = {
      id: sequenceId,
      config: structuredClone(config),  // 深拷贝避免引用问题
      candidates: candidatesResult?.candidates,
      isEstimated: candidatesResult?.isEstimated,
    };
    
    // 添加到序列
    setAttackSequence((current) => [...current, newItem]);
    
    // 清空攻击配置（保留 hash 设置）
    clearAttackConfig();
    
    // 显示提示
    showToast(language === "zh" ? "已加入攻击序列" : "Added to attack sequence");
    return true;
  }

  // 将预设转换为攻击配置
  function presetToAttackConfig(preset: PresetConfig): AttackConfig {
    return {
      hashMode: preset.hashMode || "",
      attackMode: preset.attackMode,
      hashText: null,
      hashFile: null,
      dictionaryPath: preset.dictionaryPath || null,
      dictionaryPath2: preset.dictionaryPath2 || null,
      dictionaryPaths: preset.dictionaryPaths || [],
      useRules: preset.useRules || false,
      useLeftRule: preset.useLeftRule || false,
      useRightRule: preset.useRightRule || false,
      leftRule: preset.leftRule || null,
      rightRule: preset.rightRule || null,
      mask: preset.mask || null,
      maskFile: preset.maskPath || null,
      templatePrefixMask: preset.prefixMask || null,
      templateSuffixMask: preset.suffixMask || null,
      increment: preset.increment || null,
      incrementMin: preset.incrementMin ? Number(preset.incrementMin) : null,
      incrementMax: preset.incrementMax ? Number(preset.incrementMax) : null,
      customCharset1: preset.customCharsets?.["1"] || null,
      customCharset2: preset.customCharsets?.["2"] || null,
      customCharset3: preset.customCharsets?.["3"] || null,
      customCharset4: preset.customCharsets?.["4"] || null,
      charsetFile1: null,
      charsetFile2: null,
      charsetFile3: null,
      charsetFile4: null,
      rulePaths: preset.rulePaths || [],
      taskName: null,
      optimizedKernel: null,
      workloadProfile: null,
      deviceTypes: [],
      deviceIds: null,
      candidates: preset.candidates != null ? BigInt(preset.candidates) : undefined,
      isEstimated: preset.isEstimated,
    };
  }

  // 批量添加预设到攻击序列
  async function addPresetsToSequence(presets: PresetConfig[]) {
    if (presets.length === 0) return;


    // 收集所有预设引用的文件路径（去重）
    const filePathSet = new Set<string>();
    for (const preset of presets) {
      if (preset.dictionaryPath) filePathSet.add(preset.dictionaryPath);
      if (preset.dictionaryPath2) filePathSet.add(preset.dictionaryPath2);
      if (preset.dictionaryPaths) preset.dictionaryPaths.forEach(p => filePathSet.add(p));
      if (preset.maskPath) filePathSet.add(preset.maskPath);
      if (preset.rulePaths) preset.rulePaths.forEach(p => filePathSet.add(p));
    }
    
    // 检查文件是否存在
    const missingFiles = await Promise.all(
      Array.from(filePathSet).map(async path => ({ path, exists: await invoke('check_file_exists', { path }) }))
    ).then(results => results.filter(r => !r.exists).map(r => r.path));
    
    // 如果有文件不存在，显示错误提示并返回
    if (missingFiles.length > 0) {
      const errorMsg = language === "zh"
        ? `以下文件不存在，无法添加预设：\n${missingFiles.join('\n')}`
        : `The following files do not exist, cannot add presets:\n${missingFiles.join('\n')}`;
      setError(errorMsg);
      return;
    }

    // 切换到任务配置页面
    setActiveTab("config");

    // 将所有预设转换为攻击序列项
    const newSequenceItems: AttackSequenceItem[] = presets.map(preset => {
      const sequenceId = `seq-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      const config = presetToAttackConfig(preset);
      
      // 计算候选数量
      const candidatesResult = calculateCandidates(
        config,
        preset.attackMode,
        maskEstimate,
        resources,
        customResources,
        userDictionaries,
        sequenceId
      );

      return {
        id: sequenceId,
        config: structuredClone(config),
        candidates: candidatesResult?.candidates,
        isEstimated: candidatesResult?.isEstimated,
      };
    });

    // 添加到攻击序列
    setAttackSequence((current) => [...current, ...newSequenceItems]);

    // 显示提示
    const message = language === "zh" 
      ? `已将 ${presets.length} 个预设添加到攻击序列` 
      : `${presets.length} presets added to attack sequence`;
    showToast(message);
  }

  // 从攻击序列中移除项
  function removeFromAttackSequence(id: string) {
    setAttackSequence((current) => current.filter(item => item.id !== id));
  }

  // 清空攻击序列
  function clearAttackSequence() {
    setAttackSequence([]);
  }

  // 攻击序列项上移
  function moveSequenceUp(index: number) {
    setAttackSequence((current) => {
      if (index <= 0) return current;
      const newSequence = [...current];
      [newSequence[index - 1], newSequence[index]] = [newSequence[index], newSequence[index - 1]];
      return newSequence;
    });
  }

  // 攻击序列项下移
  function moveSequenceDown(index: number) {
    setAttackSequence((current) => {
      if (index >= current.length - 1) return current;
      const newSequence = [...current];
      [newSequence[index], newSequence[index + 1]] = [newSequence[index + 1], newSequence[index]];
      return newSequence;
    });
  }

  // 攻击序列项置顶
  function moveSequenceToTop(index: number) {
    setAttackSequence((current) => {
      if (index <= 0) return current;
      const newSequence = [...current];
      const [removed] = newSequence.splice(index, 1);
      newSequence.unshift(removed);
      return newSequence;
    });
  }

  // 攻击序列项置底
  function moveSequenceToBottom(index: number) {
    setAttackSequence((current) => {
      if (index >= current.length - 1) return current;
      const newSequence = [...current];
      const [removed] = newSequence.splice(index, 1);
      newSequence.push(removed);
      return newSequence;
    });
  }

  function startQueue() {
    setQueueItems((current) => current.map((item) => item.status === "failed" ? { ...item, status: "pending", error: undefined } : item));
    setQueuePaused(false);
    showToast(queueText(language).resumed);
  }

  function pauseQueue() {
    setQueuePaused(true);
    showToast(queueText(language).paused);
  }

  function skipQueuedTask(id: string) {
    setQueueItems((current) => current.map((item) => item.id === id && item.status === "pending"
      ? { ...item, status: "skipped", finishedAt: new Date().toISOString() }
      : item));
  }

  function restoreQueuedTask(id: string) {
    setQueueItems((current) => 
      current.map(item => 
        item.id === id ? { ...item, status: "pending" as QueueStatus } : item
      )
    );
  }

  function updateQueueOrder(items: QueueItem[]) {
    setQueueItems(items);
  }

  function removeQueuedTask(id: string) {
    setQueueItems((current) => current.filter((item) => !(item.id === id && item.status !== "running")));
  }

  async function startSingleTask(id: string) {
    const item = queueItems.find(i => i.id === id);
    if (!item) return;
    
    setQueueItems(current => current.map(item => 
      item.id === id ? { ...item, status: "running" as QueueStatus, startedAt: new Date().toISOString(), error: undefined } : item
    ));
    
    setRunning(true);
    setLogs([]);
    try {
      let response: StartResponse;
    
      // 总是尝试恢复进度（如果有 taskId）
      if (item.taskId) {
        try {
          response = await invoke<StartResponse>("restore_attack", { taskId: item.taskId });
        } catch (restoreErr) {
          // 恢复失败，自动回退到重新执行
          //showToast(text.restoreFailed);
          const configForBackend = {
            ...item.config,
            candidates: typeof item.config.candidates === 'string'
              ? parseInt(item.config.candidates, 10)
              : typeof item.config.candidates === 'bigint'
                ? Number(item.config.candidates)
                : item.config.candidates,
          };
          response = await invoke<StartResponse>("start_attack", { config: configForBackend });
        }
      } else {
        const configForBackend = {
          ...item.config,
          candidates: typeof item.config.candidates === 'string'
            ? parseInt(item.config.candidates, 10)
            : typeof item.config.candidates === 'bigint'
              ? Number(item.config.candidates)
              : item.config.candidates,
        };
        response = await invoke<StartResponse>("start_attack", { config: configForBackend });
      }
      
      setQueueItems(current => current.map(item => 
        item.id === id ? { ...item, taskId: response.taskId } : item
      ));
      setTaskId(response.taskId);
      setSelectedTaskId(response.taskId);
      setBackendCommand(response.commandPreview);
    } catch (err) {
      setQueueItems(current => current.map(item => 
        item.id === id ? { ...item, status: "failed" as QueueStatus, finishedAt: new Date().toISOString(), error: String(err) } : item
      ));
      setError(String(err));
      setRunning(false);
    }
  }

  async function pauseSingleTask(id: string) {
    if (stopping) return;
    setStopping(true);

    // 找到任务获取 taskId
    const item = queueItems.find(i => i.id === id);
    if (!item) return;
    
    // 保存当前进度信息
    const currentProgress = latestStatus?.progress as [number, number] | undefined;
    const currentEstimatedStop = latestStatus?.estimated_stop as number | undefined;

    // 设置任务为暂停状态，保留进度信息
    setQueueItems(current => current.map(item => 
      item.id === id ? { 
        ...item, 
        status: "stopped" as QueueStatus, 
        finishedAt: new Date().toISOString(),
        progress: currentProgress,
        estimatedStop: currentEstimatedStop
      } : item
    ));
    
    // 使用主面板的停止逻辑，传递 taskId
    if (item.taskId) {
      try {
        await invoke("stop_attack", { taskId: item.taskId });
        showToast(text.stopRequested);
      } catch (err) {
        setError(String(err));
        setStopping(false);
      }
    } else {
      setStopping(false);
    }
    
    setRunning(false);
  }

  function clearCompletedQueueItems() {
    setQueueItems((current) => current.filter((item) => item.status === "pending" || item.status === "running"));
    showToast(queueText(language).clearDone);
  }

  async function startQueuedItem(item: QueueItem) {
    if (queueStartingRef.current) return;
    queueStartingRef.current = true;
    setQueueItems((current) => current.map((entry) => entry.id === item.id
      ? { ...entry, status: "running", startedAt: new Date().toISOString(), error: undefined }
      : entry));
    setLogs([]);
    setLatestStatus(null);
    setBackendCommand("");
    try {
      let response: StartResponse;

      // 如果已有 taskId（之前运行过），优先尝试从 hashcat 检查点文件恢复进度
      if (item.taskId) {
        try {
          response = await invoke<StartResponse>("restore_attack", { taskId: item.taskId });
        } catch (restoreErr) {
          // 恢复失败（如 restore 文件不存在或已损坏），回退到从头开始
          showToast(text.restoreFailed);
          const configForBackend = {
            ...item.config,
            candidates: typeof item.config.candidates === 'string'
              ? parseInt(item.config.candidates, 10)
              : typeof item.config.candidates === 'bigint'
                ? Number(item.config.candidates)
                : item.config.candidates,
          };
          response = await invoke<StartResponse>("start_attack", { config: configForBackend });
        }
      } else {
        const configForBackend = {
          ...item.config,
          candidates: typeof item.config.candidates === 'string'
            ? parseInt(item.config.candidates, 10)
            : typeof item.config.candidates === 'bigint'
              ? Number(item.config.candidates)
              : item.config.candidates,
        };
        response = await invoke<StartResponse>("start_attack", { config: configForBackend });
      }

      setQueueItems((current) => current.map((entry) => entry.id === item.id ? { ...entry, taskId: response.taskId } : entry));
      setTaskId(response.taskId);
      setSelectedTaskId(response.taskId);
      setBackendCommand(response.commandPreview);
      setRunning(true);
      setActiveTab("queue");
      setQueueTerminalExpanded(true);
      await refreshTasks();
    } catch (err) {
      setQueueItems((current) => current.map((entry) => entry.id === item.id
        ? { ...entry, status: "failed", finishedAt: new Date().toISOString(), error: String(err) }
        : entry));
      setError(String(err));
    } finally {
      queueStartingRef.current = false;
    }
  }

  function applyAiSuggestionFromText(content: string) {
    const suggestion = parseAiSuggestedConfig(content);
    if (!suggestion) {
      showToast(text.noAiSuggestion);
      return;
    }

    if (typeof suggestion.hashMode === "string") setHashMode(suggestion.hashMode);
    if (typeof suggestion.attackMode === "number") setAttackMode(suggestion.attackMode);
    if (typeof suggestion.hashText === "string") setHashText(suggestion.hashText);
    if (typeof suggestion.hashFile === "string") setHashFile(suggestion.hashFile);
    if (typeof suggestion.mask === "string") setMask(suggestion.mask);
    if (typeof suggestion.dictionaryPath === "string") setDictionaryPath(suggestion.dictionaryPath);
    if (Array.isArray(suggestion.rulePaths)) setRulePaths(suggestion.rulePaths);
    setActiveTab("config");
    showToast(text.aiSuggestionApplied);
  }


  function showToast(message: string) {
    setToast(message);
    window.setTimeout(() => setToast(""), 1600);
  }

  function dismissFirstGuide() {
    localStorage.setItem(FIRST_GUIDE_STORAGE_KEY, "1");
    setGuideDismissed(true);
  }

  function handleAdvancedCancel() {
    // 恢复之前保存的配置
    setDeviceIds(savedDeviceIds);
    setDeviceTypes(savedDeviceTypes);
    setWorkloadProfile(savedWorkloadProfile);
    setOptimizedKernel(savedOptimizedKernel);
    setSkipDuplicateHashOnCrack(savedSkipDuplicateHashOnCrack);
    setAdvancedOpen(false);
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark"><Hash size={22} /></div>
          <div>
            <p className="eyebrow">hashcatGUI</p>
            <h1>hashcatGUI</h1>
          </div>
        </div>
        <div className="health-strip">
          <HealthItem icon={<ShieldCheck size={15} />} label="Hashcat" value={info?.available ? info.version ?? text.appReady : text.appMissing} tone={info?.available ? "ok" : "warn"} />
          <HealthItem icon={<Cpu size={15} />} label={text.taskHealth} value={running ? text.taskBusy : text.taskIdle} tone={running ? "warn" : "ok"} />
          <button className="topbar-button help" type="button" onClick={() => setHelpOpen(true)}><HelpCircle size={16} />{text.helpTitle}</button>
          <button className="topbar-button about" type="button" onClick={() => setAboutOpen(true)}><Info size={16} />{text.aboutTitle}</button>
          <button className="topbar-button advanced" type="button" onClick={() => {
            // 保存当前配置作为快照
            setSavedDeviceIds(deviceIds);
            setSavedDeviceTypes([...deviceTypes]);
            setSavedWorkloadProfile(workloadProfile);
            setSavedOptimizedKernel(optimizedKernel);
            setSavedSkipDuplicateHashOnCrack(skipDuplicateHashOnCrack);
            setAdvancedOpen(true);
          }}><Sliders size={16} />{text.advancedSettings}</button>
          <button className="topbar-button settings" type="button" onClick={() => setSettingsOpen(true)} title={text.settingsTitle}><Settings size={17} />{text.settingsTitle}</button>
          <button className="icon-button" type="button" onClick={() => void refreshCurrentData()} title={text.refresh}><RefreshCcw size={17} /></button>
        </div>
      </header>

      {info && !info.available && !guideDismissed && (
        <section className="first-guide">
          <div>
            <strong>{language === "zh" ? "首次启动提示" : "First Start Guide"}</strong>
            <span>
              {language === "zh"
                ? "当前未检测到 hashcat。打开设置里的 Hashcat 更新，可下载安装到工具目录；也可以使用完整版便携包自带的 hashcat。"
                : "hashcat was not detected. Open Hashcat Update in Settings to install it into the tool folder, or use the full portable package with bundled hashcat."}
            </span>
          </div>
          <button className="ghost-button" type="button" onClick={() => {
            setSettingsOpen(false);
            setUpdateOpen(true);
            if (!updateInfo) void checkHashcatUpdate();
          }}>{text.hashcatUpdate}</button>
          <button className="icon-button" type="button" onClick={dismissFirstGuide} aria-label={language === "zh" ? "关闭引导" : "Close guide"}><X size={14} /></button>
        </section>
      )}
      {error && <Notice message={error} details={explainError(error, language)} onClose={() => setError("")} />}
      {toast && <div className="toast">{toast}</div>}
      {settingsOpen && (
        <DialogErrorBoundary fallback={text.settingsTitle}>
          <AiSettingsDialog language={language} setLanguage={setLanguage} text={text} settings={aiSettings} onClose={() => setSettingsOpen(false)} onOpenUpdate={() => {
            setSettingsOpen(false);
            setUpdateOpen(true);
            if (!updateInfo) void checkHashcatUpdate();
          }} hashcatPathStatus={hashcatPathStatus} onHashcatPathChange={async (path) => {
            try {
              const next = path
                ? await invoke<HashcatPathStatus>("set_hashcat_install_dir", { path })
                : await invoke<HashcatPathStatus>("clear_hashcat_install_dir");
              setHashcatPathStatus(next);
              await refreshInfo();
              await refreshHashModes();
              setUpdateInfo(null);
            } catch (err) {
              setError(String(err));
            }
          }} onSave={async (settings) => {
            try {
              const saved = await invoke<AiSettings>("save_ai_settings", { settings });
              setAiSettings(saved);
              setSettingsOpen(false);
            } catch (err) {
              setError(String(err));
            }
          }} />
        </DialogErrorBoundary>
      )}
      {updateOpen && (
        <DialogErrorBoundary fallback={text.hashcatUpdate}>
          <HashcatUpdateDialog
            info={updateInfo}
            logs={updateLogs}
            running={updateRunning}
            text={text}
            onCheck={checkHashcatUpdate}
            onClose={() => setUpdateOpen(false)}
            onInstall={installHashcatUpdate}
          />
        </DialogErrorBoundary>
      )}
      {helpOpen && (
        <DialogErrorBoundary fallback={text.helpTitle}>
          <HelpDialog
            config={{
              hashMode,
              attackMode,
              hashText,
              hashFile,
              mask,
              dictionaryPath,
              rulePaths,
              question: "",
            }}
            text={text}
            onClose={() => setHelpOpen(false)}
            onStartAi={startHelpAi}
          />
        </DialogErrorBoundary>
      )}
      {advancedOpen && (
        <DialogErrorBoundary fallback={text.deviceControl}>
          <AdvancedSettingsDialog
            deviceIds={deviceIds}
            deviceTypes={deviceTypes}
            text={text}
            workloadProfile={workloadProfile}
            optimizedKernel={optimizedKernel}
            skipDuplicateHashOnCrack={skipDuplicateHashOnCrack}
            onDeviceIdsChange={setDeviceIds}
            onToggleDeviceType={(type) => setDeviceTypes((current) => current.includes(type) ? current.filter((item) => item !== type) : [...current, type])}
            onWorkloadChange={setWorkloadProfile}
            onOptimizedKernelChange={setOptimizedKernel}
            onSkipDuplicateHashOnCrackChange={setSkipDuplicateHashOnCrack}
            onClose={() => setAdvancedOpen(false)}
            onCancel={handleAdvancedCancel}
            onResetToDefault={resetToDefault}
          />
        </DialogErrorBoundary>
      )}
      {aboutOpen && (
        <AboutDialog 
          language={language} 
          onClose={() => setAboutOpen(false)}
          updateStatus={updateStatus}
          latestVersion={latestVersion}
          onCheckUpdate={async () => {
            setUpdateStatus("checking");
            try {
              const latest = await invoke<string>("check_update");
              const hasUpdate = latest !== null && latest !== pkg.version;
              setLatestVersion(latest || "");
              setUpdateStatus(hasUpdate ? "available" : "latest");
            } catch (e) {
              setUpdateStatus("idle");
              console.error("检查更新失败:", e);
            }
          }}
        />
      )}
      {showUpdateDialog && updateResult && (
        <UpdateDialog
          language={language}
          hasUpdate={updateResult.hasUpdate}
          latestVersion={updateResult.latest}
          currentVersion={pkg.version}
          onClose={() => setShowUpdateDialog(false)}
          onDownload={() => setShowUpdateDialog(false)}
        />
      )}
      {aiOpen && (
        <AiAnalysisWindow
          content={aiText}
          error={aiError}
          minimized={aiMinimized}
          running={aiWindowRunning}
          taskId={aiTaskId}
          title={isHelpAiTask(aiTaskId) ? text.helpAiAnalysisTitle : text.aiAnalysisTitle}
          text={text}
          canApplySuggestion={isHelpAiTask(aiTaskId) && !aiWindowRunning && Boolean(aiText.trim())}
          onApplySuggestion={() => applyAiSuggestionFromText(aiText)}
          onClose={() => setAiOpen(false)}
          onMinimize={() => setAiMinimized(true)}
          onRestore={() => setAiMinimized(false)}
        />
      )}

      <section className="workspace">
        <nav className="side-tabs">
          {TABS.map((tab) => (
            <button className={activeTab === tab.key ? "active" : ""} key={tab.key} type="button" onClick={() => {
              setActiveTab(tab.key)
              if (tab.key === "resources") {
                setResourceTypeFilter("");
                setResourceQuery("");
              }
            }}>
              {tab.icon}
              <span>{tabLabel(tab.key, text)}</span>
              {(tab.key === "queue" || tab.key === "history" || tab.key === "resources") && (
                <span className="tab-count">
                  ({tab.key === "queue" ? queueItems.filter(item => item.status === "pending" || item.status === "running" || item.status === "stopped").length : tab.key === "resources" ? presets.length + customResources.length : tasks.length})
                </span>
              )}
            </button>
          ))}
        </nav>

        <section className="panel main-panel">
          {activeTab === "config" && (
            <ConfigTab
              attackMode={attackMode}
              dictionaryPath={dictionaryPath}
              dictionaryPath2={dictionaryPath2}
              dictionaryPaths={dictionaryPaths}
              filteredModes={filteredModes}
              hc22000Info={hc22000Info}
              handleHc22000File={handleHc22000File}
              setHc22000Info={setHc22000Info}
              selectedHc22000Indices={selectedHc22000Indices}
              hc22000SelectionMode={hc22000SelectionMode}
              setSelectedHc22000Indices={setSelectedHc22000Indices}
              setHc22000SelectionMode={setHc22000SelectionMode}
              hashFile={hashFile}
              hashMode={hashMode}
              hashText={hashText}
              hashSuggestions={hashSuggestions}
              identifyModes={identifyModes}
              identifyRaw={identifyRaw}
              identifyRunning={identifyRunning}
              mask={mask}
              maskFile={maskFile}
              maskEstimate={maskEstimate}
              customCharsets={[customCharset1, customCharset2, customCharset3, customCharset4]}
              deviceIds={deviceIds}
              deviceTypes={deviceTypes}
              templatePrefixMask={templatePrefixMask}
              templateSuffixMask={templateSuffixMask}
              modeQuery={modeQuery}
              optimizedKernel={optimizedKernel}
              preview={preview}
              results={selectedResults}
              rulePaths={rulePaths}
              running={running}
              selectedTask={selectedTask}
              useRules={useRules}
              setUseRules={setUseRules}
              leftRule={leftRule}
              rightRule={rightRule}
              setLeftRule={setLeftRule}
              setRightRule={setRightRule}
              logs={logs}
              taskName={taskName}
              workloadProfile={workloadProfile}
              language={language}
              text={text}
              chooseDictionary={() => void chooseDictionary("primary")}
              chooseDictionary2={() => void chooseDictionary("secondary")}
              chooseMultipleDictionaries={chooseMultipleDictionaries}
              removeDictionaryFromList={removeDictionaryFromList}
              moveDictionaryUp={moveDictionaryUp}
              moveDictionaryDown={moveDictionaryDown}
              moveDictionaryToTop={moveDictionaryToTop}
              moveDictionaryToBottom={moveDictionaryToBottom}
              clearDictionaryPaths={clearDictionaryPaths}
              selectedResourceTarget={selectedResourceTarget}
              setSelectedResourceTarget={setSelectedResourceTarget}
              useLeftRule={useLeftRule}
              setUseLeftRule={setUseLeftRule}
              useRightRule={useRightRule}
              setUseRightRule={setUseRightRule}
              chooseHashFile={chooseHashFile}
              chooseMaskFile={chooseMaskFile}
              chooseRules={chooseRules}
              copyResults={copyResults}
              openTaskDir={openTaskDir}
              readResultsFor={readResultsFor}
              setAttackMode={handleAttackModeChange}
              setHashMode={setHashMode}
              setHashText={setHashText}
              setMask={setMask}
              setModeQuery={setModeQuery}
              setOptimizedKernel={setOptimizedKernel}
              setTaskName={setTaskName}
              setTemplatePrefixMask={setTemplatePrefixMask}
              setTemplateSuffixMask={setTemplateSuffixMask}
              increment={increment}
              incrementMin={incrementMin}
              incrementMax={incrementMax}
              setIncrement={setIncrement}
              setIncrementMin={setIncrementMin}
              setIncrementMax={setIncrementMax}
              setCustomCharset={(slot, value) => {
                [setCustomCharset1, setCustomCharset2, setCustomCharset3, setCustomCharset4][slot - 1](value);
              }}
              charsetEnabled={charsetEnabled}
              setCharsetEnabled={setCharsetEnabled}
              charsetFiles={[charsetFile1, charsetFile2, charsetFile3, charsetFile4]}
              onClearCharsetFile={(slot) => {
                [setCharsetFile1, setCharsetFile2, setCharsetFile3, setCharsetFile4][slot - 1]("");
              }}
              setWorkloadProfile={setWorkloadProfile}
              startAttack={startAttack}
              addToQueue={addCurrentTaskToQueue}
              stopAttack={stopAttack}
              identifyHash={() => void identifyHash()}
              clearDictionary={() => setDictionaryPath("")}
              clearDictionary2={() => setDictionaryPath2("")}
              clearHashFile={() => {
                setHashFile("");
                setOriginalHashFile("");
                setHc22000Info(null);  // 同时清除 WPA 解析信息
              }}
              clearMaskFile={() => setMaskFile("")}
              setHashFile={setHashFile}
              setOriginalHashFile={setOriginalHashFile}
              originalHashFile={originalHashFile}
              setDictionaryPath={setDictionaryPath}
              removeRule={(path) => setRulePaths((current) => current.filter((item) => item !== path))}
              filteredResources={filteredResources}
              userDictionaries={userDictionaries}                              // 确保已传递
              customResources={customResources}  
              useResource={(resource) => {
                if (resource.kind === "dictionary") void useDictionary(resource.path, false);
                if (resource.kind === "rule") setRulePaths((current) => current.includes(resource.path) ? current : [...current, resource.path]);
                if (resource.kind === "mask") {
                  setAttackMode(3);
                  setMaskFile(resource.path);
                }
              }}
              useCustomResource={async (resource) => {
                // 检查资源引用的文件是否存在
                if (resource.path) {
                  const exists = await invoke('check_file_exists', { path: resource.path });
                  if (!exists) {
                    const errorMsg = language === "zh"
                      ? `资源引用的文件不存在：${resource.path}`
                      : `Resource file does not exist: ${resource.path}`;
                    setError(errorMsg);
                    return;
                  }
                }
                if (resource.type === "mask") {
                  if (attackMode === 0) setAttackMode(3);
                  // 如果有路径（掩码文件），设置掩码文件；否则设置掩码字符串
                  if (resource.path) {
                    setMaskFile(resource.path);
                    setMask("");  // 清空掩码字符串，避免冲突
                  } else {
                    setMask(resource.mask || "");
                    setMaskFile("");  // 清空掩码文件，避免冲突
                  }
                } else if (resource.type === "template") {
                  // 处理自定义模板类型
                  setAttackMode(9);
                  setTemplatePrefixMask(resource.prefixMask ?? "");
                  setTemplateSuffixMask(resource.suffixMask ?? "");
                } else if (resource.type === "charset") {
                  // 处理自定义字符集类型
                  setCharsetEnabled(true);
                  if (attackMode === 0) setAttackMode(3);
                  
                  if (resource.path) {
                    // 字符集文件：按空槽位自动填充
                    const charsetFiles = [charsetFile1, charsetFile2, charsetFile3, charsetFile4];
                    const emptySlot = charsetFiles.findIndex(f => !f);
                    
                    if (emptySlot !== -1) {
                      [setCharsetFile1, setCharsetFile2, setCharsetFile3, setCharsetFile4][emptySlot](resource.path);
                    }
                  } else if (resource.charsetValue) {
                    // 自定义字符集字符串：按指定槽位填充
                    const slot = Number(resource.charsetSlot ?? "1");
                    [setCustomCharset1, setCustomCharset2, setCustomCharset3, setCustomCharset4][slot - 1]?.(resource.charsetValue);
                  }
                } else if (resource.type === "rule") {
                  // 处理自定义规则类型
                  if (resource.ruleValue && resource.ruleType) {
                    // 如果是手动输入的规则值，设置左规则或右规则
                    // 切换到字典组合模式
                    if (resource.ruleType === "left") {
                      if (![0, 1, 6].includes(attackMode)) {
                        setAttackMode(0);
                      }
                      setUseRules(true);
                      setUseLeftRule(true);
                      setLeftRule(resource.ruleValue);
                    } else {
                      if (![1, 7].includes(attackMode)) {
                        setAttackMode(1);
                      }
                      setUseRightRule(true);
                      setRightRule(resource.ruleValue);
                    }
                  } else if (resource.path) {
                    // 如果是规则文件，设置规则文件路径
                    setAttackMode(0);
                    const path = resource.path;
                    setRulePaths((current) => current.includes(path) ? current : [...current, path]);
                  }
                } else if (resource.type === "dictionary" && resource.path) {
                  // 添加对字典类型的处理
                  if (attackMode === 3) setAttackMode(0);
                  void useDictionary(resource.path, false);
                }
              }}
              useUserDictionary={(dict) => {
                void useDictionary(dict.path, false);
              }}
              groups={groups}
              manageResources={manageResources}
              presets={presets}              // 新增
              presetGroups={presetGroups}    // 新增
              usePreset={usePreset}          // 新增
              onUseAllPresets={addPresetsToSequence}
              clearAttackConfig={clearAttackConfig}
              attackSequence={attackSequence}
              onAddToSequence={addToAttackSequence}
              onRemoveFromSequence={removeFromAttackSequence}
              onClearSequence={clearAttackSequence}
              onMoveSequenceUp={moveSequenceUp}
              onMoveSequenceDown={moveSequenceDown}
              onMoveSequenceToTop={moveSequenceToTop}
              onMoveSequenceToBottom={moveSequenceToBottom}
              canAddToSequence={isValidConfig(false).valid}
              tasks={tasks}
              setError={setError}
              ruleEditorTarget={ruleEditorTarget}
              openRuleEditor={(target) => setRuleEditorTarget(target)}
              onRuleEditorApply={(rule, target) => {
                if (target === "right") {
                  setUseRules(true);
                  setUseRightRule(true);
                  setRightRule(prev => (prev || "") + rule);
                } else {
                  setUseRules(true);
                  setUseLeftRule(true);
                  setLeftRule(prev => (prev || "") + rule);
                }
              }}
            />
          )}

          {activeTab === "resources" && (
            <ResourcesTab
              filteredResources={filteredResources}
              resources={resources}
              query={resourceQuery}
              setQuery={setResourceQuery}
              resourceTypeFilter={resourceTypeFilter}
              setResourceTypeFilter={setResourceTypeFilter}
              userDictionaries={userDictionaries}
              customResources={customResources}
              attackMode={attackMode}
              importDictionary={() => void chooseDictionary("primary")}
              removeDictionary={removeDictionary}
              saveCustomResource={(resource, groupId?: string) => {
                setCustomResources((current) => {
                  const existingIndex = current.findIndex(item => item.id === resource.id);
                  if (existingIndex >= 0) {
                    const updated = [...current];
                    updated[existingIndex] = resource;
                    return updated;
                  } else {
                    const maxSortOrder = current.length > 0 
                      ? Math.max(...current.map(r => r.sortOrder || 0)) 
                      : 0;
                    const newResource: CustomResource = {
                      ...resource,
                      sortOrder: maxSortOrder + 1
                    };
                    return [...current, newResource];
                  }
                });
                
                // 如果选中了分组，将新资源添加到该分组
                if (groupId) {
                  setGroups(prev => prev.map(group => {
                    if (group.id === groupId) {
                      return { ...group, resourceIds: [...group.resourceIds, resource.id] };
                    }
                    return group;
                  }));
                }
              }}
              deleteCustomResource={(resource) => void deleteCustomResource(resource)}
              setCustomResources={setCustomResources}
              updateUserDictionaryName={updateUserDictionaryName}
              groups={groups}
              setGroups={setGroups}
              manageResources={manageResources}
              setManageResources={setManageResources}
              setActiveTab={setActiveTab}
              setAttackMode={setAttackMode}
              setHashMode={setHashMode}
              setDictionaryPaths={setDictionaryPaths}
              setDictionaryPath={setDictionaryPath}
              setDictionaryPath2={setDictionaryPath2}
              setMask={setMask}
              setMaskFile={setMaskFile}
              setPrefixMask={setTemplatePrefixMask}
              setSuffixMask={setTemplateSuffixMask}
              setUseRules={setUseRules}
              setUseLeftRule={setUseLeftRule}
              setLeftRule={setLeftRule}
              setUseRightRule={setUseRightRule}
              setRightRule={setRightRule}
              setCustomCharset={(slot, value) => {
                [setCustomCharset1, setCustomCharset2, setCustomCharset3, setCustomCharset4][slot - 1](value);
              }}
              setCharsetEnabled={setCharsetEnabled}
              setIncrement={setIncrement}
              setIncrementMin={setIncrementMin}
              setIncrementMax={setIncrementMax}
              setRulePaths={setRulePaths}
              useCustomResource={async (resource) => {
                // 检查资源引用的文件是否存在
                if (resource.path) {
                  const exists = await invoke('check_file_exists', { path: resource.path });
                  if (!exists) {
                    const errorMsg = language === "zh"
                      ? `资源引用的文件不存在：${resource.path}`
                      : `Resource file does not exist: ${resource.path}`;
                    setError(errorMsg);
                    return;  // 文件不存在，不跳转
                  }
                }
                if (resource.type === "mask") {
                  setAttackMode(3);
                  setMask(resource.mask ?? "");
                  setMaskFile(resource.path ?? "");
                } else if (resource.type === "template") {
                  setAttackMode(9);
                  setTemplatePrefixMask(resource.prefixMask ?? "");
                  setTemplateSuffixMask(resource.suffixMask ?? "");
                } else if (resource.type === "charset") {
                  setCharsetEnabled(true);
                  if (attackMode === 0) setAttackMode(3);
                  
                  if (resource.path) {
                    // 字符集文件：按空槽位自动填充
                    const charsetFiles = [charsetFile1, charsetFile2, charsetFile3, charsetFile4];
                    const emptySlot = charsetFiles.findIndex(f => !f);
                    
                    if (emptySlot !== -1) {
                      [setCharsetFile1, setCharsetFile2, setCharsetFile3, setCharsetFile4][emptySlot](resource.path);
                    }
                  } else if (resource.charsetValue) {
                    // 自定义字符集字符串：按指定槽位填充
                    const slot = Number(resource.charsetSlot ?? "1");
                    [setCustomCharset1, setCustomCharset2, setCustomCharset3, setCustomCharset4][slot - 1]?.(resource.charsetValue);
                  }
                } else if (resource.type === "rule") {
                  if (resource.ruleValue && resource.ruleType) {
                    // 如果是手动输入的规则值，设置左规则或右规则
                    // 切换到字典组合模式
                    if (resource.ruleType === "left") {
                      if (![0, 1, 6].includes(attackMode)) {
                        setAttackMode(0);
                      }
                      setUseRules(true);
                      setUseLeftRule(true);
                      setLeftRule(resource.ruleValue);
                    } else {
                      if (![1, 7].includes(attackMode)) {
                        setAttackMode(1);
                      }
                      setUseRightRule(true);
                      setRightRule(resource.ruleValue);
                    }
                  } else if (resource.path) {
                    // 如果是规则文件，设置规则文件路径
                    setAttackMode(0);
                    setUseRules(true);
                    const rulePath = resource.path;
                    setRulePaths((current) => current.includes(rulePath) ? current : [...current, rulePath]);
                  }
                }
                if (resource.type === "dictionary" && resource.path) void useDictionary(resource.path, false);
                setActiveTab("config");
              }}
              useResource={(resource) => {
                if (resource.kind === "dictionary") void useDictionary(resource.path, false);
                if (resource.kind === "rule") {
                  if (selectedResourceTarget === "primary") {
                    setUseRules(true);
                    setRulePaths((current) => current.includes(resource.path) ? current : [...current, resource.path]);
                  }
                }
                if (resource.kind === "mask") {
                  setAttackMode(3);
                  setMaskFile(resource.path);
                }
                if (resource.kind === "charset") {
                  // 处理字符集文件
                  setCharsetEnabled(true);
                  if (attackMode === 0) setAttackMode(3);
                  
                  if (resource.path) {
                    // 字符集文件：按空槽位自动填充
                    const charsetFiles = [charsetFile1, charsetFile2, charsetFile3, charsetFile4];
                    const emptySlot = charsetFiles.findIndex(f => !f);
                    
                    if (emptySlot !== -1) {
                      [setCharsetFile1, setCharsetFile2, setCharsetFile3, setCharsetFile4][emptySlot](resource.path);
                    }
                  }
                }
                setActiveTab("config");
              }}
              text={text}
              simpleMode={simpleMode}
              setSimpleMode={setSimpleMode}
              clearAttackConfig={clearAttackConfig}
              presets={presets}
              setPresets={setPresets}
              presetGroups={presetGroups}
              setPresetGroups={setPresetGroups}
              onAddToSequence={addToAttackSequence}
              showToast={showToast}
              addPresetsToSequence={addPresetsToSequence}
              onRefreshPresets={loadAllDataFromBackend}
              onRefreshResources={refreshResources}
              setError={setError}
            />
          )}

          {activeTab === "queue" && (
            <QueueTab
              items={queueItems}
              language={language}
              terminalExpanded={queueTerminalExpanded}
              setTerminalExpanded={setQueueTerminalExpanded}
              paused={queuePaused}
              running={running}
              stopping={stopping}
              logs={logs}
              hashModes={hashModes}
              onClearDone={clearCompletedQueueItems}
              onPause={pauseQueue}
              onRemove={removeQueuedTask}
              onSkip={skipQueuedTask}
              onRestore={restoreQueuedTask}
              onStart={startQueue}
              onUpdateOrder={updateQueueOrder}
              onStartSingleTask={startSingleTask}
              onPauseSingleTask={pauseSingleTask}
              text={text}
              latestStatus={latestStatus}
              simpleMode={simpleMode}
              setSimpleMode={setSimpleMode}
              onUpdateItem={setQueueItems}
            />
          )}

          {activeTab === "history" && (
            <HistoryTab
              statusFilter={historyStatusFilter}
              setStatusFilter={setHistoryStatusFilter}
              searchQuery={historySearchQuery}
              setSearchQuery={setHistorySearchQuery}
              analyzeLog={analyzeLog}
              aiRunningTaskIds={aiRunningTaskIds}
              taskLog={selectedTaskLog}
              readTaskLogFor={readTaskLogFor}
              copyResults={copyResults}
              deleteTask={deleteTask}
              exportResults={exportResults}
              loadTask={loadTask}
              openTaskDir={openTaskDir}
              readResultsFor={readResultsFor}
              rerunTask={rerunTask}
              restoreTask={restoreTask}
              results={selectedResults}
              selectedTask={selectedTask}
              selectedTaskId={selectedTaskId}
              setSelectedTaskId={setSelectedTaskId}
              tasks={tasks}
              language={language}
              text={text}
              hashModes={hashModes}
              simpleMode={simpleMode}
              setSimpleMode={setSimpleMode}
            />
          )}
        </section>
          <aside className="status-rail">
          {/* 添加控制区域 */}
          <section className="control-panel fixed-top">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Control</p>
                <h2>{activeTab === "config" ? text.attackControl : queueText(language).title}</h2>
              </div>
            </div>
            {/* 控制按钮区域 */}
            <div className="control-actions">
              {/* 第一行：开始和暂停 */}
              <div className="action-row compact-actions justify-center full-width-buttons">
                <button className="primary-button" type="button" onClick={startAttack} disabled={running || stopping}>
                  <Play size={17} />{text.start}
                </button>
                <button className="danger-button" type="button" onClick={() => { stopAttack(); pauseQueue(); }} disabled={stopping || (!running && queuePaused)}>
                  <Square size={15} />{text.stop}
                </button>
              </div>
              {/* 第二行：加入队列 */}
              <div className="action-row justify-center full-width-buttons">
                <button className="ghost-button" type="button" onClick={addCurrentTaskToQueue} disabled={!isValidConfig()}>
                  <FileClock size={16} />{queueText(language).add}
                </button>
              </div>
              {/* 第三行：开始队列 */}
              <div className="action-row justify-center full-width-buttons">
                <button className="primary-button" type="button" onClick={startQueue} disabled={stopping || !queuePaused || !queueItems.some(item => item.status === "pending" || item.status === "stopped")}>
                  <Play size={16} />{queueText(language).start}
                </button>
              </div>
            </div>
          </section>
          {/* 设备性能面板 - 可滚动 */}
          <div className="scrollable-panel">
            <DevicePerformancePanel
              backendInfo={info?.backendInfo ?? null}
              backendRaw={info?.backendRaw ?? ""}
              latestStatus={latestStatus}
              scanState={deviceScanState}
              onRefreshDevices={refreshDeviceInfo}
              text={text}
              language={language}
            />
          </div>
        </aside>
      </section>
    </main>
  );
}

function ConfigTab(props: {
  attackMode: AttackMode;
  dictionaryPath: string;
  dictionaryPath2: string;
  dictionaryPaths: string[];
  filteredModes: HashModeInfo[];
  hc22000Info: Hc22000Info | null;
  handleHc22000File: (filePath: string) => void;
  setHc22000Info: (info: Hc22000Info | null) => void;
  selectedHc22000Indices: number[];                    // 新增：选中的行索引
  hc22000SelectionMode: 'multi' | 'single';             // 新增：选择模式
  setSelectedHc22000Indices: (indices: number[]) => void; // 新增：设置选中索引
  setHc22000SelectionMode: (mode: 'multi' | 'single') => void; // 新增：设置选择模式
  hashFile: string;
  hashMode: string;
  hashText: string;
  hashSuggestions: HashModeSuggestion[];
  identifyModes: HashModeInfo[];
  identifyRaw: string;
  identifyRunning: boolean;
  mask: string;
  maskFile: string;
  maskEstimate: MaskEstimate | null;
  customCharsets: string[];
  charsetFiles: string[];
  onClearCharsetFile: (slot: 1 | 2 | 3 | 4) => void;
  deviceIds: string;
  deviceTypes: string[];
  templatePrefixMask: string;
  templateSuffixMask: string;
  modeQuery: string;
  optimizedKernel: boolean;
  preview: string;
  results: ResultsResponse | null;
  rulePaths: string[];
  running: boolean;
  selectedTask?: TaskManifest;
  useRules: boolean;
  setUseRules: (enabled: boolean) => void;
  logs: LogPayload[];
  taskName: string;
  workloadProfile: number;
  language: Language;
  text: UiText;
  chooseDictionary: () => void;
  chooseDictionary2: () => void;
  leftRule: string;
  rightRule: string;
  setLeftRule: (rule: string) => void;
  setRightRule: (rule: string) => void;
  selectedResourceTarget: "primary" | "secondary";
  setSelectedResourceTarget: (target: "primary" | "secondary") => void;
  useLeftRule: boolean;
  setUseLeftRule: (enabled: boolean) => void;
  useRightRule: boolean;
  setUseRightRule: (enabled: boolean) => void;
  chooseHashFile: () => void;
  chooseMaskFile: () => void;
  chooseRules: () => void;
  copyResults: () => void;
  openTaskDir: () => void;
  readResultsFor: (id?: string) => void;
  setAttackMode: (mode: AttackMode) => void;
  setHashMode: (mode: string) => void;
  setHashText: (text: string) => void;
  setMask: (mask: string) => void;
  setModeQuery: (query: string) => void;
  setOptimizedKernel: (enabled: boolean) => void;
  setTaskName: (name: string) => void;
  setTemplatePrefixMask: (mask: string) => void;
  setTemplateSuffixMask: (mask: string) => void;
  increment: boolean;
  incrementMin: string;
  incrementMax: string;
  setIncrement: (enabled: boolean) => void;
  setIncrementMin: (value: string) => void;
  setIncrementMax: (value: string) => void;
  setCustomCharset: (slot: 1 | 2 | 3 | 4, value: string) => void;
  charsetEnabled: boolean;
  setCharsetEnabled: (enabled: boolean) => void;
  setWorkloadProfile: (value: number) => void;
  startAttack: () => void;
  addToQueue: () => void;
  stopAttack: () => void;
  identifyHash: () => void;
  clearDictionary: () => void;
  clearDictionary2: () => void;
  clearHashFile: () => void;
  clearMaskFile: () => void;
  removeRule: (path: string) => void;
  setHashFile: (path: string) => void;
  setOriginalHashFile: (path: string) => void;
  originalHashFile: string;
  chooseMultipleDictionaries: () => void;
  removeDictionaryFromList: (path: string) => void;
  moveDictionaryUp: (index: number) => void;
  moveDictionaryDown: (index: number) => void;
  moveDictionaryToTop: (index: number) => void;
  moveDictionaryToBottom: (index: number) => void;
  clearDictionaryPaths: () => void;
  setDictionaryPath: (path: string) => void;  // 新增
  filteredResources: ResourceInfo[];
  userDictionaries: UserDictionary[];
  customResources: CustomResource[];
  useResource: (resource: ResourceInfo) => void;
  useCustomResource: (resource: CustomResource) => void;
  useUserDictionary: (dict: UserDictionary) => void;
  groups?: { id: string; name: string; resourceIds: string[]; expanded: boolean }[];
  manageResources?: (CustomResource & { source: "custom" | "user" })[];
  presets: PresetConfig[];
  presetGroups: PresetGroup[];
  usePreset: (preset: PresetConfig) => void;
  onUseAllPresets?: (presets: PresetConfig[]) => void;
  clearAttackConfig: () => void;
  tasks: TaskManifest[];                // 新增：用于检测已破解的hash
  setError: (message: string) => void
  onAddToSequence: () => void;
  onRemoveFromSequence: (id: string) => void;
  onClearSequence: () => void;
  onMoveSequenceUp: (index: number) => void;
  onMoveSequenceDown: (index: number) => void;
  onMoveSequenceToTop: (index: number) => void;
  onMoveSequenceToBottom: (index: number) => void;
  canAddToSequence: boolean;
  attackSequence: AttackSequenceItem[];
  openRuleEditor: (target: "left" | "right") => void;
  ruleEditorTarget: "left" | "right";
  onRuleEditorApply: (rule: string, target: "left" | "right") => void;
}) {
  const [maskHelp, setMaskHelp] = useState(false);
  {/*const [terminalExpanded, setTerminalExpanded] = useState(false);*/}
  const [hashInputMode, setHashInputMode] = useState<"file" | "text">("file");
  const [resourcePickerOpen, setResourcePickerOpen] = useState(false);
  const [selectedResourceKind, setSelectedResourceKind] = useState<"dictionary" | "rule" | "mask" | "charset" | "template">("dictionary");
  const [selectedRuleType, setSelectedRuleType] = useState<"left" | "right">();
  const [ruleEditorOpen, setRuleEditorOpen] = useState(false);

  const [attackModeDropdownOpen, setAttackModeDropdownOpen] = useState(false);
  const [presetPickerOpen, setPresetPickerOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const charsetEnabled = props.charsetEnabled;
  const setCharsetEnabled = props.setCharsetEnabled;
  const setSelectedResourceTarget = props.setSelectedResourceTarget;
  const [commandExpanded, setCommandExpanded] = useState(false);
  const text = props.text;

  // 当掩码文件变化时，自动取消递增掩码和自定义字符集
  useEffect(() => {
    if (props.attackMode === 3 && props.maskFile) {
      props.setCharsetEnabled(false);
    }
  }, [props.attackMode, props.maskFile]);

  // 点击外部关闭攻击模式下拉框
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as HTMLElement;
      // 检查点击是否在下拉框外部
      if (dropdownRef.current && !dropdownRef.current.contains(target)) {
        setAttackModeDropdownOpen(false);
      }
    };
    
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // 打开资源选择器
  const openResourcePicker = (kind: "dictionary" | "rule" | "mask" | "charset" | "template", target: "primary" | "secondary" = "primary", ruleType?: "left" | "right") => {
    setSelectedResourceKind(kind);
    setSelectedResourceTarget(target);
    setSelectedRuleType(ruleType);
    setResourcePickerOpen(true);
  };



  return (
    <div className="tab-content config-tab">
      
      <div className="config-tab-top">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">{text.attackSettings}</p>
            <h2>{text.attackConfigTitle}</h2>
          </div>
        </div>
        <div className="action-config-row">
          <div className="config-grid">
            <label className="field task-name-horizontal">
              <span>{text.taskName}</span>
              <input value={props.taskName} onChange={(event) => props.setTaskName(event.currentTarget.value)} placeholder={text.taskNamePlaceholder} />
            </label>
          </div>
        </div>
      </div>
      <div className="config-tab-body">
        <div className="config-section">
          <div className="hash-input-row"> 
            <section className="hash-mode-picker">
              <div className="hash-mode-row">
                <div className="section-header">
                  <Hash size={16} />
                  <span>{text.hashModePicker}</span>
                </div>
                <div className="hash-mode-dropdown-wrapper">
                  <div className="hash-mode-dropdown">
                    <button className="hash-mode-dropdown-trigger" type="button" onClick={(e) => {
                      e.stopPropagation();
                      const dropdown = document.querySelector('.hash-mode-list');
                      dropdown?.classList.toggle('open');
                    }}>
                      <span>{props.hashMode ? props.filteredModes.find(m => String(m.mode) === props.hashMode)?.name || `Mode ${props.hashMode}` : text.selectHashMode}</span>
                      <ChevronDown size={16} />
                    </button>
                    <div className="hash-mode-list" onClick={(e) => e.stopPropagation()}>
                      <div className="hash-mode-search-inner">
                        <input 
                          value={props.modeQuery} 
                          onChange={(event) => props.setModeQuery(event.currentTarget.value)} 
                          placeholder={text.hashModeSearch} 
                          autoFocus
                        />
                        {props.modeQuery && <button className="hash-search-clear" type="button" onClick={() => props.setModeQuery("")}><X size={14} /></button>}
                      </div>
                      {props.filteredModes.slice(0, 120).map((mode) => (
                        <button className={String(mode.mode) === props.hashMode ? "active" : ""} key={`${mode.mode}-${mode.name}`} type="button" onClick={() => {
                          props.setHashMode(String(mode.mode));
                          props.setModeQuery("");
                          const dropdown = document.querySelector('.hash-mode-list');
                          dropdown?.classList.remove('open');
                        }}>
                          <strong>{mode.mode}</strong>
                          <span>{mode.name}</span>
                          <em>{mode.category}</em>
                        </button>
                      ))}
                      {!props.filteredModes.length && <div className="empty-state mode-empty">{text.noHashModes}</div>}
                    </div>
                  </div>
                </div>
                <label className="field hash-mode-field">
                  <input value={props.hashMode} onChange={(event) => props.setHashMode(event.currentTarget.value)} placeholder={`${text.hashMode}: ${text.hashModePlaceholder}`} />
                </label>
                <button className="official-identify-btn" type="button" onClick={() => {
                  const panel = document.querySelector('.hash-suggestion-panel');
                  panel?.classList.add('show');
                  props.identifyHash();
                }} disabled={props.identifyRunning}>
                  {props.identifyRunning ? text.hashIdentifyRunning : text.hashOfficialIdentify}
                </button>
              </div>
            </section>
            <div className="hash-input-stack">
              <div className="hash-input-tab-container">
                <div className="hash-input-tabs">
                  <button className={hashInputMode === "file" ? "active" : ""} type="button" onClick={() => setHashInputMode("file")}>{text.hashFileMode}</button>
                  <button className={hashInputMode === "text" ? "active" : ""} type="button" onClick={() => setHashInputMode("text")}>{text.hashTextMode}</button>
                </div>
                <div className="hash-input-content">
                  {hashInputMode === "file" && (
                    <div className="hash-input-file">
                      <FileButton
                        label=""
                        value={props.originalHashFile || props.hashFile}
                        empty={text.hashFileDrop}
                        onClick={props.chooseHashFile}
                        onClear={props.clearHashFile}
                        clearText={text.cancel}
                        onDrop={(paths) => {
                          if (paths.length > 0) {
                            props.setHashFile(paths[0]);
                            props.setHashText("");
                            
                            // 检测 .hc22000 文件
                            if (paths[0].toLowerCase().endsWith(".hc22000")) {
                              props.setHashMode("22000");
                              
                              // 调用父组件传递的处理函数
                              if (props.handleHc22000File) {
                                props.handleHc22000File(paths[0]);
                              }
                            } else {
                              props.setHc22000Info(null);
                            }
                          }
                        }}
                      />
                    </div>
                  )}
                  {hashInputMode === "text" && (
                    <div className="hash-input-main">
                      <textarea 
                        className="hash-textarea" 
                        value={props.hashText} 
                        onChange={(event) => props.setHashText(event.currentTarget.value)} 
                        onBlur={() => {
                          void (async () => {
                            if (props.hashText.trim()) {
                              const crackedTaskId = await checkHashAlreadyCracked(props.hashText, props.tasks);
                              if (crackedTaskId) {
                                const crackedTask = props.tasks.find(t => t.taskId === crackedTaskId);
                                const passwords = crackedTask?.extractedPasswords?.slice(0, 3) || [];
                                const passwordText = passwords.length > 0 
                                  ? `\n${text.passwordLabel}: ${passwords.join(", ")}` 
                                  : "";
                                const message = `${text.hashAlreadyCracked}${passwordText}`;
                                props.setError(message);
                              }
                            }
                          })();
                        }}
                        placeholder={text.hashInputPlaceholder} 
                        spellCheck={false} 
                      />
                    </div>
                  )}
                </div>
              </div>

              <div className="hash-suggestion-full">
                <HashSuggestionPanel
                  suggestions={props.hashSuggestions}
                  identifyModes={props.identifyModes}
                  identifyRaw={props.identifyRaw}
                  identifyRunning={props.identifyRunning}
                  text={text}
                  onApply={props.setHashMode}
                  onIdentify={() => {}}
                />
              </div>
              {(() => {
                return props.hc22000Info;
              })() && (
                <div className="hc22000-analysis">
                  <div className="section-header">
                    <Info size={16} />
                    <span>{props.language === "zh" ? "WPA 信息分析" : "WPA Info Analysis"}</span>
                    <span style={{ marginLeft: 'auto', fontSize: '0.7rem', opacity: 0.7 }}>
                      {props.language === "zh" 
                        ? `共 ${props.hc22000Info!.entries.length} 条记录` 
                        : `${props.hc22000Info!.entries.length} entries`}
                    </span>
                  </div>
                  <table className="hc22000-table">
                    <thead>
                      <tr>
                        {/* 表头勾选框 - 全选按钮 */}
                        <th>
                          <input
                            type="checkbox"
                            checked={props.hc22000SelectionMode === 'multi' && 
                              props.selectedHc22000Indices.length === props.hc22000Info!.entries.length}
                            onChange={() => {
                              // 点击表头勾选框，切换回多选模式并全选
                              props.setHc22000SelectionMode('multi');
                              props.setSelectedHc22000Indices(
                                props.hc22000Info!.entries.map((_, i) => i)
                              );
                              // 清空 hashText，使用 hashFile
                              props.setHashText("");
                            }}
                          />
                        </th>
                        <th>ESSID</th>
                        <th>BSSID</th>
                        <th>AP_MAC</th>
                      </tr>
                    </thead>
                    <tbody>
                      {props.hc22000Info!.entries.map((entry, index) => (
                        <tr 
                          key={index}
                          className={props.selectedHc22000Indices.includes(index) ? 'selected' : ''}
                        >
                          {/* 每行的勾选框 */}
                          <td>
                            <input
                              type="checkbox"
                              checked={props.selectedHc22000Indices.includes(index)}
                              onChange={() => {
                                if (props.hc22000SelectionMode === 'multi') {
                                  // 多选模式下点击：切换到单选模式，只选中当前行
                                  props.setHc22000SelectionMode('single');
                                  props.setSelectedHc22000Indices([index]);
                                  props.setHashText(entry.lineText);
                                } else {
                                  // 单选模式下点击：只能切换到其他行，不能取消选中
                                  if (!props.selectedHc22000Indices.includes(index)) {
                                    // 如果当前行未选中，选中当前行（自动取消之前选中的行）
                                    props.setSelectedHc22000Indices([index]);
                                    props.setHashText(entry.lineText);
                                  }
                                }
                              }}
                            />
                          </td>
                          <td>{entry.essid}</td>
                          <td>{entry.bssid}</td>
                          <td>{entry.apMac}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="config-section">
          <div className="attack-settings">
            <div className="attack-settings-head">
              <div className="attack-mode-switch">
                <div className="section-header">
                  <Settings size={16} />
                  <span>{text.attackModePicker}</span>
                </div>
                <div className="attack-mode-dropdown-wrapper">          
                  <div className="attack-mode-dropdown" ref={dropdownRef}>
                    <button className="attack-mode-dropdown-trigger" type="button" onClick={(e) => {
                      e.stopPropagation();
                      setAttackModeDropdownOpen(!attackModeDropdownOpen);
                    }}>
                      <span>{attackModeLabel(props.attackMode, text)}</span>
                      <ChevronDown size={16} />
                    </button>
                    <div className={`attack-mode-list ${attackModeDropdownOpen ? 'open' : ''}`} onClick={(e) => e.stopPropagation()}>
                      {([
                        { mode: 0 as AttackMode, label: text.dictionary },
                        { mode: 1 as AttackMode, label: text.dictionaryCombo },
                        { mode: 3 as AttackMode, label: text.mask },
                        { mode: 6 as AttackMode, label: text.hybridDictMask },
                        { mode: 7 as AttackMode, label: text.hybridMaskDict },
                        { mode: 9 as AttackMode, label: text.templateAttack },
                      ]).map((item) => (
                        <button
                          className={props.attackMode === item.mode ? "active" : ""}
                          key={item.mode}
                          type="button"
                          onClick={() => {
                            props.setAttackMode(item.mode);
                            setAttackModeDropdownOpen(false);
                          }}
                        >
                          {item.label} 
                          <span className="attack-mode-flag"> (-a {item.mode === 9 ? "0" : item.mode})</span>
                        </button>
                      ))}
                    </div>
                  </div>
                  <button type="button" className="preset-picker-btn" onClick={() => setPresetPickerOpen(true)}>
                    {text.usePreset}
                  </button>
                  <button 
                    type="button" 
                    className="preset-picker-btn sequence-btn"
                    onClick={() => props.onAddToSequence()}
                    disabled={!props.canAddToSequence}
                  >
                    {text.addToSequence}
                  </button>
                </div>
              </div>
            </div>
            <div className="resource-stack">
              {/* 字典模式：支持单/多字典自动识别 */}
              {props.attackMode === 0 && (
                <div className="attack-side-by-side">
                  <div className="attack-left">
                    {/* 统一的字典选择器 */}
                    <div className="dictionary-selector">
                      {/* 字典列表 */}
                      <div className="multi-dictionary-box">
                        <div className="line-title">
                          <span>{text.dictionaryFile}</span>
                          <button type="button" onClick={props.chooseMultipleDictionaries}>
                              {text.add}
                          </button>
                          <button type="button" onClick={() => openResourcePicker("dictionary")}>
                              {text.useResource}  {/* 新增：使用资源按钮 */}
                          </button>
                          {/* 规则开关 - 移到标题栏右侧 */}
                          <label className="toggle-line rules-toggle inline">
                              <input 
                                  type="checkbox" 
                                  checked={props.useRules} 
                                  onChange={(event) => props.setUseRules(event.currentTarget.checked)} 
                              />
                              <span>{text.useRules}</span>
                          </label>
                        </div>
                        
                        {/* 字典列表显示 */}
                        <div className="pill-list">
                            {props.dictionaryPaths.length > 0 ? (
                                props.dictionaryPaths.map((path, index) => (
                                    <span className="path-pill" key={`${path}-${index}`} title={path}>
                                        {/* 序号 */}
                                        <span className="path-index">{index + 1}</span>
                                        {/* 路径（带省略） */}
                                        <span className="path-name">{shortPath(path)}</span>
                                        {/* 操作按钮 */}
                                        <div className="path-actions">
                                            {/* 置顶按钮 - 始终显示 */}
                                            <button 
                                                type="button" 
                                                onClick={() => props.moveDictionaryToTop(index)} 
                                                disabled={index === 0}
                                                title={props.language === "zh" ? "置顶" : "Move to top"}
                                            >
                                                <ArrowUpToLine size={12} />
                                            </button>
                                            {/* 置底按钮 - 新增 */}
                                            <button 
                                                type="button" 
                                                onClick={() => props.moveDictionaryToBottom(index)} 
                                                disabled={index === props.dictionaryPaths.length - 1}
                                                title={props.language === "zh" ? "置底" : "Move to bottom"}
                                            >
                                                <ArrowDownToLine size={12} />
                                            </button>
                                            {/* 上移按钮 - 始终显示 */}
                                            <button 
                                                type="button" 
                                                onClick={() => props.moveDictionaryUp(index)} 
                                                disabled={index === 0}
                                                title={props.language === "zh" ? "上移" : "Move up"}
                                            >
                                                <ChevronUp size={12} />
                                            </button>
                                            {/* 下移按钮 - 始终显示 */}
                                            <button 
                                                type="button" 
                                                onClick={() => props.moveDictionaryDown(index)} 
                                                disabled={index === props.dictionaryPaths.length - 1}
                                                title={props.language === "zh" ? "下移" : "Move down"}
                                            >
                                                <ChevronDown size={12} />
                                            </button>
                                            {/* 删除按钮 */}
                                            <button 
                                                type="button" 
                                                onClick={() => props.removeDictionaryFromList(path)} 
                                                title={props.language === "zh" ? "删除" : "Remove"}
                                            >
                                                <X size={12} />
                                            </button>
                                        </div>
                                    </span>
                                ))
                            ) : props.dictionaryPath ? (
                                // 单字典模式：显示单个可操作的字典项
                                <span className="path-pill" key={props.dictionaryPath} title={props.dictionaryPath}>
                                    <span className="path-index">1</span>
                                    <span className="path-name">{shortPath(props.dictionaryPath)}</span>
                                    <div className="path-actions">
                                        <button 
                                            type="button" 
                                            onClick={() => props.clearDictionary()} 
                                            title={props.language === "zh" ? "删除" : "Remove"}
                                        >
                                            <X size={12} />
                                        </button>
                                    </div>
                                </span>
                            ) : (
                                <span className="muted">{text.notSelected}</span>
                            )}
                        </div>
                        
                        {/* 多字典提示（仅当有多个字典时显示） */}
                        {props.dictionaryPaths.length > 1 && (
                          <div className="multi-dict-hint">
                            {props.language === "zh" 
                              ? `已选择 ${props.dictionaryPaths.length} 个字典，任务将依次执行，破解成功后跳过后续字典` 
                              : `${props.dictionaryPaths.length} dictionaries selected. Tasks run sequentially. Success skips remaining.`}
                          </div>
                        )}
                        {(props.dictionaryPaths.length > 0 || props.dictionaryPath) && (
                          <button className="clear-file-button" type="button" onClick={props.clearDictionaryPaths}>
                              <X size={13} />{props.language === "zh" ? "清空" : "Clear"}
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                  
                  {/* 规则文件设置（仅勾选时显示） */}
                  {props.useRules && (
                    <div className="attack-right">
                      <div className="rule-box">
                        <div className="line-title">
                          <span>{props.text.rule}</span>
                          <button type="button" onClick={() => { props.openRuleEditor("left"); setRuleEditorOpen(true); }}>
                            {text.ruleEditor}
                          </button>
                          <button type="button" onClick={() => openResourcePicker("rule", "primary", "left")}>
                            {text.useResource}
                          </button>
                        </div>
                        <div className="mask-input-wrapper">
                          <input 
                            className="mask-input" 
                            value={props.leftRule} 
                            onChange={(event) => props.setLeftRule(event.currentTarget.value)} 
                            placeholder={text.rulePlaceholder} 
                            spellCheck={false} 
                          />
                        </div>
                        <div className="line-title">
                          <span>{text.rulesFile}</span>
                          <button type="button" onClick={props.chooseRules}>{text.add}</button>
                          <button type="button" onClick={() => openResourcePicker("rule")}>{text.useResource}</button>
                        </div>
                        <div className="pill-list">
                          {props.rulePaths.length ? props.rulePaths.map((path) => (
                            <span className="path-pill" key={path} title={path}>
                              {shortPath(path)}
                              <button type="button" onClick={() => props.removeRule(path)}>
                                <X size={12} />
                              </button>
                            </span>
                          )) : <span className="muted">{text.noRules}</span>}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
              {props.attackMode === 1 && (
                <div className="dictionary-combo">
                  {/* 第一个字典 - 左字典 */}
                  <div className="attack-side-by-side">
                    <div className="attack-left">
                      <FileButton 
                        label={text.dictionaryFile}
                        value={props.dictionaryPath} 
                        empty={text.notSelected} 
                        onClick={props.chooseDictionary} 
                        onClear={props.clearDictionary} 
                        clearText={text.cancel}
                        useResourceText={text.useResource}
                        onUseResource={() => openResourcePicker("dictionary")}
                        extraContent={
                          <label className="toggle-line rules-toggle">
                            <input type="checkbox" checked={props.useLeftRule} onChange={(event) => props.setUseLeftRule(event.currentTarget.checked)} />
                            <span>{text.useRules}</span>
                          </label>
                        }
                      />
                    </div>
                    {/* 左规则输入框 - 只有勾选使用规则时才显示 */}
                    {props.useLeftRule && (
                      <div className="attack-right">
                        <div className="mask-card">
                          <div className="line-title">
                            <span>{text.leftRule}</span>
                            <button type="button" onClick={() => { props.openRuleEditor("left"); setRuleEditorOpen(true); }}>{text.ruleEditor}</button>
                            <button type="button" onClick={() => openResourcePicker("rule", "primary", "left")}>{text.useResource}</button>
                          </div>
                          <div className="mask-input-wrapper">
                            <input className="mask-input" value={props.leftRule} onChange={(event) => props.setLeftRule(event.currentTarget.value)} placeholder={text.rulePlaceholder} spellCheck={false} />
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                  
                  {/* 第二个字典 - 右字典 */}
                  <div className="attack-side-by-side">
                    <div className="attack-left">
                      <FileButton 
                        label={text.dictionaryFile}
                        value={props.dictionaryPath2} 
                        empty={text.notSelected} 
                        onClick={props.chooseDictionary2} 
                        onClear={props.clearDictionary2} 
                        clearText={text.cancel}
                        useResourceText={text.useResource}
                        onUseResource={() => openResourcePicker("dictionary", "secondary")}
                        extraContent={
                          <label className="toggle-line rules-toggle">
                            <input type="checkbox" checked={props.useRightRule} onChange={(event) => props.setUseRightRule(event.currentTarget.checked)} />
                            <span>{text.useRules}</span>
                          </label>
                        }
                      />
                    </div>
                    {/* 右规则输入框 - 只有勾选使用规则时才显示 */}
                    {props.useRightRule && (
                      <div className="attack-right">
                        <div className="mask-card">
                          <div className="line-title">
                            <span>{text.rightRule}</span>
                            <button type="button" onClick={() => { props.openRuleEditor("right"); setRuleEditorOpen(true); }}>{text.ruleEditor}</button>
                            <button type="button" onClick={() => openResourcePicker("rule", "secondary", "right")}>{text.useResource}</button>
                          </div>
                          <div className="mask-input-wrapper">
                            <input className="mask-input" value={props.rightRule} onChange={(event) => props.setRightRule(event.currentTarget.value)} placeholder={text.rulePlaceholder} spellCheck={false} />
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
              {/* 字典+掩码模式：左边字典，右边掩码 */}
              {props.attackMode === 6 && (
                <div className="attack-side-by-side">
                  <div className="attack-left">
                    <FileButton 
                      label={text.dictionaryFile}
                      value={props.dictionaryPath} 
                      empty={text.notSelected} 
                      onClick={props.chooseDictionary} 
                      onClear={props.clearDictionary} 
                      clearText={text.cancel}
                      useResourceText={text.useResource}
                      onUseResource={() => openResourcePicker("dictionary")}
                      extraContent={
                        <label className="toggle-line rules-toggle">
                          <input type="checkbox" checked={props.useLeftRule} onChange={(event) => props.setUseLeftRule(event.currentTarget.checked)} />
                          <span>{text.useRules}</span>
                        </label>
                      }
                    />
                    {props.useLeftRule && (
                      <div className="mask-card">
                        <div className="line-title">
                          <span>{text.leftRule}</span>
                          <button type="button" onClick={() => { props.openRuleEditor("left"); setRuleEditorOpen(true); }}>{text.ruleEditor}</button>
                          <button type="button" onClick={() => openResourcePicker("rule", "primary", "left")}>{text.useResource}</button>
                        </div>
                        <div className="mask-input-wrapper">
                          <input className="mask-input" value={props.leftRule} onChange={(event) => props.setLeftRule(event.currentTarget.value)} placeholder={text.rulePlaceholder} spellCheck={false} />
                        </div>
                      </div>
                    )}
                  </div>
                  <div className="attack-right">
                    <div className="mask-card">
                      <div className="line-title">
                        <span>{text.mask}</span>
                        <button type="button" onClick={() => setMaskHelp((value) => !value)}>{text.help}</button>
                        <button type="button" onClick={() => openResourcePicker("mask")}>{text.useResource}</button>
                      </div>
                      <div className="mask-input-wrapper">
                        <div className="mask-input-row">
                          <input className="mask-input" value={props.mask} onChange={(event) => props.setMask(event.currentTarget.value)} placeholder={text.maskPlaceholder} spellCheck={false} />
                          <div className="increment-toggle">
                            <label className="toggle-line">
                              <input type="checkbox" checked={props.increment} onChange={(event) => props.setIncrement(event.currentTarget.checked)} />
                              <span>{text.incrementMask}</span>
                            </label>
                          </div>
                        </div>
                        {props.increment && (
                          <div className="increment-range-below">
                            <label className="field"><span>{text.incrementMin}</span><input value={props.incrementMin} onChange={(event) => props.setIncrementMin(event.currentTarget.value.replace(/\D/g, "").slice(0, 2))} placeholder="1" /></label>
                            <label className="field"><span>{text.incrementMax}</span><input value={props.incrementMax} onChange={(event) => props.setIncrementMax(event.currentTarget.value.replace(/\D/g, "").slice(0, 2))} placeholder="8" /></label>
                          </div>
                        )}
                      </div>
                      <CustomCharsetEditor 
                        values={props.customCharsets} 
                        onChange={props.setCustomCharset} 
                        text={text} 
                        attackMode={props.attackMode}
                        enabled={charsetEnabled}
                        onToggle={setCharsetEnabled}
                        onOpenResourcePicker={() => openResourcePicker("charset")}
                        charsetFiles={props.charsetFiles}
                        onClearCharsetFile={props.onClearCharsetFile}
                      />
                      <MaskEstimateCard estimate={props.maskEstimate} text={text} />
                      {maskHelp && <div className="mask-help"><p>{text.maskHelp}</p><code>JinriPIN_Salt_2015?d?d?d?d</code></div>}
                    </div>
                  </div>
                </div>
              )}
              {/* 掩码+字典模式：左边掩码，右边字典 */}
              {props.attackMode === 7 && (
                <div className="attack-side-by-side">
                  <div className="attack-left">
                    <div className="mask-card">
                      <div className="line-title">
                        <span>{text.mask}</span>
                        <button type="button" onClick={() => setMaskHelp((value) => !value)}>{text.help}</button>
                        <button type="button" onClick={() => openResourcePicker("mask")}>{text.useResource}</button>
                      </div>
                      <div className="mask-input-wrapper">
                        <div className="mask-input-row">
                          <input className="mask-input" value={props.mask} onChange={(event) => props.setMask(event.currentTarget.value)} placeholder={text.maskPlaceholder} spellCheck={false} />
                          <div className="increment-toggle">
                            <label className="toggle-line">
                              <input type="checkbox" checked={props.increment} onChange={(event) => props.setIncrement(event.currentTarget.checked)} />
                              <span>{text.incrementMask}</span>
                            </label>
                          </div>
                        </div>
                        {props.increment && (
                          <div className="increment-range-below">
                            <label className="field"><span>{text.incrementMin}</span><input value={props.incrementMin} onChange={(event) => props.setIncrementMin(event.currentTarget.value.replace(/\D/g, "").slice(0, 2))} placeholder="1" /></label>
                            <label className="field"><span>{text.incrementMax}</span><input value={props.incrementMax} onChange={(event) => props.setIncrementMax(event.currentTarget.value.replace(/\D/g, "").slice(0, 2))} placeholder="8" /></label>
                          </div>
                        )}
                      </div>
                      <CustomCharsetEditor 
                        values={props.customCharsets} 
                        onChange={props.setCustomCharset} 
                        text={text} 
                        attackMode={props.attackMode}
                        enabled={charsetEnabled}
                        onToggle={setCharsetEnabled}
                        onOpenResourcePicker={() => openResourcePicker("charset")}
                        charsetFiles={props.charsetFiles}
                        onClearCharsetFile={props.onClearCharsetFile}
                      />
                      <MaskEstimateCard estimate={props.maskEstimate} text={text} />
                      {maskHelp && <div className="mask-help"><p>{text.maskHelp}</p><code>JinriPIN_Salt_2015?d?d?d?d</code></div>}
                    </div>
                  </div>
                  <div className="attack-right">
                    <FileButton 
                      label={text.dictionaryFile}
                      value={props.dictionaryPath} 
                      empty={text.notSelected} 
                      onClick={props.chooseDictionary} 
                      onClear={props.clearDictionary} 
                      clearText={text.cancel}
                      useResourceText={text.useResource}
                      onUseResource={() => openResourcePicker("dictionary")}
                      extraContent={
                        <label className="toggle-line rules-toggle">
                          <input type="checkbox" checked={props.useRightRule} onChange={(event) => props.setUseRightRule(event.currentTarget.checked)} />
                          <span>{text.useRules}</span>
                        </label>
                      }
                    />
                    {props.useRightRule && (
                      <div className="mask-card">
                        <div className="line-title">
                          <span>{text.rightRule}</span>
                          <button type="button" onClick={() => { props.openRuleEditor("right"); setRuleEditorOpen(true); }}>{text.ruleEditor}</button>
                          <button type="button" onClick={() => openResourcePicker("rule", "secondary", "right")}>{text.useResource}</button>
                        </div>
                        <div className="mask-input-wrapper">
                          <input className="mask-input" value={props.rightRule} onChange={(event) => props.setRightRule(event.currentTarget.value)} placeholder={text.rulePlaceholder} spellCheck={false} />
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
              {/* 纯掩码模式 */}
              {props.attackMode === 3 && (
                <div className="mask-card">
                  <div className="line-title">
                    <span>{text.mask}</span>
                    <button type="button" onClick={() => setMaskHelp((value) => !value)}>{text.help}</button>
                    <button type="button" onClick={props.chooseMaskFile}>{text.file}</button>
                    <button type="button" onClick={() => openResourcePicker("mask")}>{text.useResource}</button>
                  </div>
                  <div className="mask-input-wrapper">
                    <div className="mask-input-row">
                      <input className="mask-input" value={props.mask} onChange={(event) => props.setMask(event.currentTarget.value)} placeholder={text.maskPlaceholder} spellCheck={false} disabled={!!props.maskFile}/>
                      <div className="increment-toggle">
                        <label className="toggle-line">
                          <input type="checkbox" checked={props.increment} onChange={(event) => props.setIncrement(event.currentTarget.checked)}/>
                          <span>{text.incrementMask}</span>
                        </label>
                      </div>
                    </div>
                    {props.maskFile && <span className="path-pill" title={props.maskFile}>{shortPath(props.maskFile)}<button type="button" onClick={props.clearMaskFile}><X size={12} /></button></span>}
                    {props.increment && (
                      <div className="increment-range-below">
                        <label className="field"><span>{text.incrementMin}</span><input value={props.incrementMin} onChange={(event) => props.setIncrementMin(event.currentTarget.value.replace(/\D/g, "").slice(0, 2))} placeholder="1" /></label>
                        <label className="field"><span>{text.incrementMax}</span><input value={props.incrementMax} onChange={(event) => props.setIncrementMax(event.currentTarget.value.replace(/\D/g, "").slice(0, 2))} placeholder="8" /></label>
                      </div>
                    )}
                  </div>
                  <CustomCharsetEditor 
                    values={props.customCharsets} 
                    onChange={props.setCustomCharset} 
                    text={text} 
                    attackMode={props.attackMode}
                    enabled={charsetEnabled && !props.maskFile}
                    onToggle={(enabled) => !props.maskFile && setCharsetEnabled(enabled)}
                    onOpenResourcePicker={() => openResourcePicker("charset")}
                    charsetFiles={props.charsetFiles}
                    onClearCharsetFile={props.onClearCharsetFile}
                    disabled={!!props.maskFile}
                  />
                  <MaskEstimateCard estimate={props.maskEstimate} text={text} />
                  {maskHelp && <div className="mask-help"><p>{text.maskHelp}</p><code>JinriPIN_Salt_2015?d?d?d?d</code></div>}
                </div>
              )}
              {/* 模板攻击模式 */}
              {props.attackMode === 9 && (
                <div className="mask-card">
                  <div className="line-title">
                    <span>{text.templateAttack}</span>
                    <button type="button" onClick={() => openResourcePicker("template")}>{text.useResource}</button>
                  </div>
                  <div className="template-row">
                    <label className="field">
                      <span>{text.prefixMask}</span>
                      <input className="mask-input" value={props.templatePrefixMask} onChange={(event) => props.setTemplatePrefixMask(event.currentTarget.value)} placeholder="?d?d" spellCheck={false} />
                    </label>
                    <div className="template-dictionary">
                      <FileButton 
                        label={text.dictionaryFile}
                        value={props.dictionaryPath} 
                        empty={text.notSelected} 
                        onClick={props.chooseDictionary} 
                        onClear={props.clearDictionary} 
                        clearText={text.cancel}
                        useResourceText={text.useResource}
                        onUseResource={() => openResourcePicker("dictionary")}
                      />
                    </div>
                    <label className="field">
                      <span>{text.suffixMask}</span>
                      <input className="mask-input" value={props.templateSuffixMask} onChange={(event) => props.setTemplateSuffixMask(event.currentTarget.value)} placeholder="?d?d" spellCheck={false} />
                    </label>
                  </div>
                  <div className="mask-help"><p>{text.templateHint}<code>{props.templatePrefixMask || "?d?d"} + {text.templatePreviewWord} + {props.templateSuffixMask || "?d?d"}</code></p></div>
                  <CustomCharsetEditor 
                    values={props.customCharsets} 
                    onChange={props.setCustomCharset} 
                    text={text} 
                    attackMode={props.attackMode}
                    enabled={charsetEnabled}
                    onToggle={setCharsetEnabled}
                    onOpenResourcePicker={() => openResourcePicker("charset")}
                    charsetFiles={props.charsetFiles}
                    onClearCharsetFile={props.onClearCharsetFile}
                  />
                </div>
              )}
            </div>
          </div>
        </div>

        {props.attackSequence.length > 0 && (
          <div className="config-section multi-dictionary-box">
            <div className="line-title">
              <Zap size={16} />
              <span>{text.attackSequence}</span>
              <button type="button" onClick={props.onClearSequence}>
                {text.clear}
              </button>
            </div>
            
            {/* 序列列表 */}
            <div className="pill-list">
              {props.attackSequence.map((item, index) => (
                <span key={item.id} className="path-pill">
                  {/* 序号 */}
                  <span className="path-index">{index + 1}</span>
                  
                  {/* 攻击类型信息 */}
                  <span className="path-name">
                    {attackModeLabel(item.config.attackMode, text)} · 
                    {generatePresetDetail(
                      {
                        ...item.config,
                        candidates: item.candidates?.toString(),
                        isEstimated: item.isEstimated
                      } as unknown as PresetConfig,
                      text,
                      props.language === "zh"
                    )}
                  </span>
                  
                  {/* 操作按钮 */}
                  <div className="path-actions">
                    <button type="button" onClick={() => props.onMoveSequenceToTop(index)} disabled={index === 0}>
                      <ArrowUpToLine size={12} />
                    </button>
                    <button type="button" onClick={() => props.onMoveSequenceToBottom(index)} disabled={index === props.attackSequence.length - 1}>
                      <ArrowDownToLine size={12} />
                    </button>
                    <button type="button" onClick={() => props.onMoveSequenceUp(index)} disabled={index === 0}>
                      <ChevronUp size={12} />
                    </button>
                    <button type="button" onClick={() => props.onMoveSequenceDown(index)} disabled={index === props.attackSequence.length - 1}>
                      <ChevronDown size={12} />
                    </button>
                    <button type="button" onClick={() => props.onRemoveFromSequence(item.id)}>
                      <X size={12} />
                    </button>
                  </div>
                </span>
              ))}
            </div>
            
            {/* 提示信息 */}
            <div className="multi-dict-hint">
              {props.language === "zh" 
                ? `已添加 ${props.attackSequence.length} 个攻击类型，任务将依次执行，破解成功后跳过后续任务` 
                : `${props.attackSequence.length} attack types added. Tasks run sequentially. Success skips remaining.`}
            </div>
          </div>
        )}
      </div>

      <div className="config-tab-bottom">
        <div className={commandExpanded ? "command-box expanded" : "command-box collapsed"}>
          <div className="command-box-header">
            <div className="line-title"><Terminal size={16} /><span>{text.commandPreview}</span></div>
            <button className="ghost-button terminal-toggle-button" type="button" onClick={() => setCommandExpanded((value) => !value)}>
              {commandExpanded ? text.collapse : text.expand}
            </button>
          </div>
          {commandExpanded && <code>{props.preview}</code>}
        </div>
      </div>

      {/* 规则编辑器弹窗 */}
      <RuleEditorModal
        isOpen={ruleEditorOpen}
        onClose={() => setRuleEditorOpen(false)}
        text={text}
        initialTarget={props.ruleEditorTarget}
        onApply={(rule, target) => {
          props.onRuleEditorApply(rule, target);
          setRuleEditorOpen(false);
        }}
      />

      {/* 资源选择弹窗 */}
      <ResourcePickerModal
        isOpen={resourcePickerOpen}
        onClose={() => setResourcePickerOpen(false)}
        resources={props.filteredResources}
        userDictionaries={props.userDictionaries}      // 新增
        customResources={props.customResources}        // 新增
        resourceKind={selectedResourceKind}
        text={text}
        onUseResource={props.useResource}              // 使用内置资源
        onUseCustomResource={props.useCustomResource}  // 使用自定义资源
        onUseUserDictionary={props.useUserDictionary}  // 使用用户字典
        attackMode={props.attackMode}
        ruleType={selectedRuleType}
        groups={props.groups}
      />

      {/* 预设选择弹窗 */}
      <PresetPickerModal
        isOpen={presetPickerOpen}
        onClose={() => setPresetPickerOpen(false)}
        presets={props.presets}
        presetGroups={props.presetGroups}
        text={text}
        onUsePreset={props.usePreset}
        onUseAllPresets={props.onUseAllPresets}
      />
    </div>
  );
}

function RuleEditorModal(props: {
  isOpen: boolean;
  onClose: () => void;
  text: UiText;
  onApply: (rule: string, target: "left" | "right") => void;
  initialTarget?: "left" | "right";
}) {
  const [ruleArray, setRuleArray] = useState<string[]>([]);
  const [nthCharValue, setNthCharValue] = useState<string>('');
  const [repeatValue, setRepeatValue] = useState<string>('');
  const [appendCharValue, setAppendCharValue] = useState<string>('');
  const [prependCharValue, setPrependCharValue] = useState<string>('');
  const [insertPosition, setInsertPosition] = useState<string>('');
  const [insertChar, setInsertChar] = useState<string>('');
  const [replacePosition, setReplacePosition] = useState<string>('');
  const [replaceChar, setReplaceChar] = useState<string>('');
  const [originalCharValue, setOriginalCharValue] = useState<string>('');
  const [newCharValue, setNewCharValue] = useState<string>('');
  const [repeatFirstValue, setRepeatFirstValue] = useState<string>('');
  const [repeatLastValue, setRepeatLastValue] = useState<string>('');
  const [deletePosition, setDeletePosition] = useState<string>('');
  const [extractStartPos, setExtractStartPos] = useState<string>('');
  const [extractLength, setExtractLength] = useState<string>('');
  const [deleteStartPos, setDeleteStartPos] = useState<string>('');
  const [deleteLength, setDeleteLength] = useState<string>('');
  const [deleteAllChar, setDeleteAllChar] = useState<string>('');
  const [swapPosN, setSwapPosN] = useState<string>('');
  const [swapPosM, setSwapPosM] = useState<string>('');
  const [repeatStartNValue, setRepeatStartNValue] = useState<string>('');
  const [repeatEndNValue, setRepeatEndNValue] = useState<string>('');
  const [advancedArray, setAdvancedArray] = useState<string[]>([]);
  const [advLengthN, setAdvLengthN] = useState<string>('');
  const [advLengthN2, setAdvLengthN2] = useState<string>('');
  const [advLengthN3, setAdvLengthN3] = useState<string>('');
  const [advFilterChar, setAdvFilterChar] = useState<string>('');
  const [advStartChar, setAdvStartChar] = useState<string>('');
  const [advEndChar, setAdvEndChar] = useState<string>('');
  
  // 应用规则
  const applyRule = () => {
    const advancedRule = advancedArray.join(' ');
    const normalRule = ruleArray.join('');
    const combinedRule = advancedRule && normalRule 
      ? `${advancedRule} ${normalRule}` 
      : advancedRule || normalRule;
    
    if (combinedRule) {
      props.onApply(combinedRule, targetRef.current); // ← 改调外部回调
      setRuleArray([]);
      setAdvancedArray([]);
      resetAllInputs(); // 清空所有输入框
      props.onClose();  // ← 关闭弹窗
    }
  };

  // 删除上一个添加的规则
  const deleteLastRule = () => {
    if (advancedArray.length > 0) {
      setAdvancedArray(prev => prev.slice(0, -1));
    } else if (ruleArray.length > 0) {
      setRuleArray(prev => prev.slice(0, -1));
    }
  };

  // 清空预览规则
  const clearPreview = () => {
    setRuleArray([]);
  };

  // 新增：关闭时重置所有输入
  const resetAllInputs = () => {
    setRuleArray([]);
    setAdvancedArray([]);
    setNthCharValue('');
    setRepeatValue('');
    setAppendCharValue('');
    setPrependCharValue('');
    setInsertPosition('');
    setInsertChar('');
    setReplacePosition('');
    setReplaceChar('');
    setOriginalCharValue('');
    setNewCharValue('');
    setRepeatFirstValue('');
    setRepeatLastValue('');
    setDeletePosition('');
    setExtractStartPos('');
    setExtractLength('');
    setDeleteStartPos('');
    setDeleteLength('');
    setDeleteAllChar('');
    setSwapPosN('');
    setSwapPosM('');
    setRepeatStartNValue('');
    setRepeatEndNValue('');
    setAdvLengthN('');
    setAdvLengthN2('');
    setAdvLengthN3('');
    setAdvFilterChar('');
    setAdvStartChar('');
    setAdvEndChar('');
  };
  
  const targetRef = useRef<"left" | "right">(props.initialTarget || "left");
  useEffect(() => { targetRef.current = props.initialTarget || "left"; }, [props.initialTarget, props.isOpen]);

  useEffect(() => {
    if (!props.isOpen) {
      resetAllInputs();
    }
  }, [props.isOpen]);

  if (!props.isOpen) return null; // 参考 ResourcePickerModal 的模式

  const text = props.text;
  return (
    <>
      {props.isOpen && (
        <div className="modal-overlay" onClick={() => props.onClose()}>
          <div className="rule-editor-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>{text.ruleEditor}</h2>
              <button type="button" onClick={() => props.onClose()} className="icon-button">
                <X size={20} />
              </button>
            </div>
            <div className="modal-body">
              {/* 大小写转换区域 */}
              <div className="rule-section">
                <h3>{text.caseConversion}</h3>
                <div className="rule-options">
                  {/* 第一行：小写所有字母 / 大写所有字母 */}
                  <div className="rule-row">
                    <button type="button" className={`rule-add-btn ${ruleArray.includes('l') ? 'rule-add-btn-active' : ''}`}  onClick={() => setRuleArray(prev => [...prev, 'l'])}>
                      {text.lowercaseAll}
                    </button>
                    <button type="button" className={`rule-add-btn ${ruleArray.includes('u') ? 'rule-add-btn-active' : ''}`}  onClick={() => setRuleArray(prev => [...prev, 'u'])}>
                      {text.uppercaseAll}
                    </button>
                  </div>
                  {/* 第二行：首字母大写其余小写 / 首字母小写其余大写 */}
                  <div className="rule-row">
                    <button type="button" className={`rule-add-btn ${ruleArray.includes('c') ? 'rule-add-btn-active' : ''}`}  onClick={() => setRuleArray(prev => [...prev, 'c'])}>
                      {text.capitalizeFirst}
                    </button>
                    <button type="button" className={`rule-add-btn ${ruleArray.includes('C') ? 'rule-add-btn-active' : ''}`}  onClick={() => setRuleArray(prev => [...prev, 'C'])}>
                      {text.lowercaseFirst}
                    </button>
                  </div>
                  {/* 第三行：反转大小写 */}
                  <div className="rule-row">
                    <button type="button" className={`rule-add-btn ${ruleArray.includes('t') ? 'rule-add-btn-active' : ''}`}  onClick={() => setRuleArray(prev => [...prev, 't'])}>
                      {text.toggleCase}
                    </button>
                  </div>
                  {/* 第四行：切换第N个字符大小写 */}
                  <div className="rule-row">
                    <button type="button" className={`rule-add-btn ${ruleArray.some(r => r.startsWith('T')) ? 'rule-add-btn-active' : ''}`}  onClick={() => setRuleArray(prev => [...prev, `T${nthCharValue || '3'}`])}>
                      {text.toggleNthChar}
                    </button>
                    <input
                      type="number"
                      min="1"
                      value={nthCharValue}
                      onChange={(e) => setNthCharValue(e.target.value)}
                      className="nth-input"
                    />
                  </div>
                </div>
              {/* 字符新增区域 */}
              <div className="rule-section">
                <h3>{text.characterChange} ({text.add})</h3>
                
                  {/* 第五行：后面添加 */}
                  <div className="rule-row">
                    <button type="button" className={`rule-add-btn ${ruleArray.some(r => r.startsWith('^')) ? 'rule-add-btn-active' : ''}`} onClick={() => {
                      // 对每个输入字符添加 ^ 前缀
                      const chars = (prependCharValue || '^').split('');
                      const rule = chars.map(c => `^${c}`).join('');
                      setRuleArray(prev => [...prev, rule]);
                    }}>
                      {text.appendBefore}
                    </button>
                    <input
                      type="text"
                      value={prependCharValue}
                      onChange={(e) => setPrependCharValue(e.target.value)}
                      className="nth-input"
                      placeholder={text.char}
                    />
                    <button type="button" className={`rule-add-btn ${ruleArray.some(r => r.startsWith('$')) ? 'rule-add-btn-active' : ''}`} onClick={() => {
                      // 对每个输入字符添加 $ 前缀
                      const chars = (appendCharValue || '$').split('');
                      const rule = chars.map(c => `$${c}`).join('');
                      setRuleArray(prev => [...prev, rule]);
                    }}>
                      {text.appendAfter}
                    </button>
                    <input
                      type="text"
                      value={appendCharValue}
                      onChange={(e) => setAppendCharValue(e.target.value)}
                      className="nth-input"
                      placeholder={text.char}
                    />
                  </div>
                  {/* 第七行：在n位置插入字符 */}
                  <div className="rule-row">
                    <button type="button" 
                      className={`rule-add-btn ${ruleArray.some(r => r.startsWith('i')) ? 'rule-add-btn-active' : ''}`} 
                      onClick={() => {
                        const pos = insertPosition || '1';
                        const c = insertChar || 'x';
                        setRuleArray(prev => [...prev, `i${pos}${c}`]);
                      }}>
                      {text.insertAtPosition}
                    </button>
                    <input
                      type="number"
                      min="1"
                      value={insertPosition}
                      onChange={(e) => setInsertPosition(e.target.value)}
                      className="nth-input"
                      placeholder={text.position}
                    />
                    <input
                      type="text"
                      maxLength={1}
                      value={insertChar}
                      onChange={(e) => setInsertChar(e.target.value.slice(0, 1))}
                      className="nth-input"
                      placeholder={text.char}
                    />
                    <label> (eg i2@, abcd → ab@cd)</label>
                  </div>
                  {/* 第二行：重复n次字符串 */}
                  <div className="rule-row">
                    <button type="button" className={`rule-add-btn ${ruleArray.includes('d') ? 'rule-add-btn-active' : ''}`} onClick={() => setRuleArray(prev => [...prev, 'd'])}>
                      {text.duplicateString}
                    </button>
                    <label> (123 → 123123)</label>
                    <button type="button" className={`rule-add-btn ${ruleArray.some(r => r.startsWith('p')) ? 'rule-add-btn-active' : ''}`} onClick={() => setRuleArray(prev => [...prev, `p${repeatValue || '2'}`])}>
                      {text.repeatNtimes}
                    </button>
                    <input
                      type="number"
                      min="2"
                      value={repeatValue}
                      onChange={(e) => setRepeatValue(e.target.value)}
                      className="nth-input"
                      placeholder={text.number}
                    />
                  </div>

                  {/* 第十行：重复第一个字符n次 / 重复最后一个字符n次 */}
                  <div className="rule-row">
                    <button type="button" 
                      className={`rule-add-btn ${ruleArray.some(r => r.startsWith('z')) ? 'rule-add-btn-active' : ''}`} 
                      onClick={() => {
                        const n = repeatFirstValue || '2';
                        setRuleArray(prev => [...prev, `z${n}`]);
                      }}>
                      {text.repeatFirstChar}
                    </button>
                    <input
                      type="number"
                      min="1"
                      value={repeatFirstValue}
                      onChange={(e) => setRepeatFirstValue(e.target.value)}
                      className="nth-input"
                      placeholder={text.number}
                    />
                    <label> (eg 1, 123 → 1123)</label>
                  </div>
                  <div className="rule-row">
                    <button type="button" 
                      className={`rule-add-btn ${ruleArray.some(r => r.startsWith('Z')) ? 'rule-add-btn-active' : ''}`} 
                      onClick={() => {
                        const n = repeatLastValue || '2';
                        setRuleArray(prev => [...prev, `Z${n}`]);
                      }}>
                      {text.repeatLastChar}
                    </button>
                    <input
                      type="number"
                      min="1"
                      value={repeatLastValue}
                      onChange={(e) => setRepeatLastValue(e.target.value)}
                      className="nth-input"
                      placeholder={text.number}
                    />
                    <label> (eg 1, 123 → 1233)</label>
                  </div>
                  
                  {/* 第十一行：重复每个字符 */}
                  <div className="rule-row">
                    <button type="button" 
                      className={`rule-add-btn ${ruleArray.includes('q') ? 'rule-add-btn-active' : ''}`} 
                      onClick={() => setRuleArray(prev => [...prev, 'q'])}>
                      {text.repeatEachChar}
                    </button>
                    <label> (eg abc → aabbcc)</label>
                  </div>
                  
                  {/* 第三行：末尾添加字符串的反转 */}
                  <div className="rule-row">
                    <button type="button" className={`rule-add-btn ${ruleArray.includes('f') ? 'rule-add-btn-active' : ''}`} onClick={() => setRuleArray(prev => [...prev, 'f'])}>
                      {text.appendReverse}
                    </button>
                    <label> (123 → 123321)</label>
                  </div>
                  {/* 第二十行：重复开始的N个字符 */}
                  <div className="rule-row">
                    <button type="button" 
                      className={`rule-add-btn ${ruleArray.some(r => r.startsWith('y')) ? 'rule-add-btn-active' : ''}`} 
                      onClick={() => {
                        const n = repeatStartNValue || '1';
                        setRuleArray(prev => [...prev, `y${n}`]);
                      }}>
                      {text.repeatStartN}
                    </button>
                    <input
                      type="number"
                      min="1"
                      value={repeatStartNValue}
                      onChange={(e) => setRepeatStartNValue(e.target.value)}
                      className="nth-input"
                      placeholder={text.number}
                    />
                    <label> (eg y2, abcd → ababcd)</label>
                  </div>

                  {/* 第二十一行：重复末尾的N个字符 */}
                  <div className="rule-row">
                    <button type="button" 
                      className={`rule-add-btn ${ruleArray.some(r => r.startsWith('Y')) ? 'rule-add-btn-active' : ''}`} 
                      onClick={() => {
                        const n = repeatEndNValue || '1';
                        setRuleArray(prev => [...prev, `Y${n}`]);
                      }}>
                      {text.repeatEndN}
                    </button>
                    <input
                      type="number"
                      min="1"
                      value={repeatEndNValue}
                      onChange={(e) => setRepeatEndNValue(e.target.value)}
                      className="nth-input"
                      placeholder={text.number}
                    />
                    <label> (eg Y2, abcd → abcdcd)</label>
                  </div>
              </div>
              {/* 字符替换区域 */}
              <div className="rule-section">
                <h3>{text.characterChange} ({text.replace}&{text.reorder})</h3>
                <div className="rule-options">
                  {/* 第一行：反转整个字符串*/}
                  <div className="rule-row">
                    <button type="button" className={`rule-add-btn ${ruleArray.includes('r') ? 'rule-add-btn-active' : ''}`} onClick={() => setRuleArray(prev => [...prev, 'r'])}>
                      {text.reverseString}
                    </button>
                    <label> (123 → 321)</label>
                  </div>
                  {/* 第四行：末尾字符移动到首部 */}
                  <div className="rule-row">
                    <button type="button" className={`rule-add-btn ${ruleArray.includes('{') ? 'rule-add-btn-active' : ''}`} onClick={() => setRuleArray(prev => [...prev, '{'])}>
                      {text.moveFirstToEnd}
                    </button>
                    <label> (123 → 231)</label>
                  </div>
                  <div className="rule-row">
                    <button type="button" className={`rule-add-btn ${ruleArray.includes('}') ? 'rule-add-btn-active' : ''}`} onClick={() => setRuleArray(prev => [...prev, '}'])}>
                      {text.moveLastToFirst}
                    </button>
                    <label> (123 → 312)</label>
                  </div>
                  {/* 第十七行：交换首部两个字符位置 */}
                  <div className="rule-row">
                    <button type="button" 
                      className={`rule-add-btn ${ruleArray.includes('k') ? 'rule-add-btn-active' : ''}`} 
                      onClick={() => setRuleArray(prev => [...prev, 'k'])}>
                      {text.swapFirstTwo}
                    </button>
                    <label> (eg abc → bac)</label>
                  </div>

                  {/* 第十八行：交换末尾两个字符位置 */}
                  <div className="rule-row">
                    <button type="button" 
                      className={`rule-add-btn ${ruleArray.includes('K') ? 'rule-add-btn-active' : ''}`} 
                      onClick={() => setRuleArray(prev => [...prev, 'K'])}>
                      {text.swapLastTwo}
                    </button>
                    <label> (eg abc → acb)</label>
                  </div>

                  {/* 第十九行：交换位置N和M的字符 */}
                  <div className="rule-row">
                    <button type="button" 
                      className={`rule-add-btn ${ruleArray.some(r => r.startsWith('*')) ? 'rule-add-btn-active' : ''}`} 
                      onClick={() => {
                        const n = swapPosN || '1';
                        const m = swapPosM || '2';
                        setRuleArray(prev => [...prev, `*${n}${m}`]);
                      }}>
                      {text.swapPositions}
                    </button>
                    <input
                      type="number"
                      min="1"
                      value={swapPosN}
                      onChange={(e) => setSwapPosN(e.target.value)}
                      className="nth-input"
                      placeholder={text.positionN}
                    />
                    <input
                      type="number"
                      min="1"
                      value={swapPosM}
                      onChange={(e) => setSwapPosM(e.target.value)}
                      className="nth-input"
                      placeholder={text.positionM}
                    />
                    <label> (eg *13, abcde → cbade)</label>
                  </div>
                  {/* 第八行：替换n位置字符 */}
                  <div className="rule-row">
                    <button type="button" 
                      className={`rule-add-btn ${ruleArray.some(r => r.startsWith('o')) ? 'rule-add-btn-active' : ''}`} 
                      onClick={() => {
                        const pos = replacePosition || '1';
                        const c = replaceChar || 'x';
                        setRuleArray(prev => [...prev, `o${pos}${c}`]);
                      }}>
                      {text.replaceAtPosition}
                    </button>
                    <input
                      type="number"
                      min="1"
                      value={replacePosition}
                      onChange={(e) => setReplacePosition(e.target.value)}
                      className="nth-input"
                      placeholder={text.position}
                    />
                    <input
                      type="text"
                      maxLength={1}
                      value={replaceChar}
                      onChange={(e) => setReplaceChar(e.target.value.slice(0, 1))}
                      className="nth-input"
                      placeholder={text.char}
                    />
                    <label> (eg o2a, 123 → 1a3)</label>
                  </div>

                  {/* 第九行：替换字符a为b */}
                  <div className="rule-row">
                    <button type="button" 
                      className={`rule-add-btn ${ruleArray.some(r => r.startsWith('s')) ? 'rule-add-btn-active' : ''}`} 
                      onClick={() => {
                        const a = originalCharValue || 'a';
                        const b = newCharValue || 'b';
                        setRuleArray(prev => [...prev, `s${a}${b}`]);
                      }}>
                      {text.replaceChar}
                    </button>
                    <input
                      type="text"
                      maxLength={1}
                      value={originalCharValue}
                      onChange={(e) => setOriginalCharValue(e.target.value.slice(0, 1))}
                      className="nth-input"
                      placeholder={text.originalChar}
                    />
                    <input
                      type="text"
                      maxLength={1}
                      value={newCharValue}
                      onChange={(e) => setNewCharValue(e.target.value.slice(0, 1))}
                      className="nth-input"
                      placeholder={text.replaceWith}
                    />
                  </div>

                </div>
                {/* 字符删除区域 */}
                <div className="rule-section">
                  <h3>{text.characterChange} ({text.delete})</h3>

                  {/* 第十二行：删除首字符 / 删除尾字符 */}
                  <div className="rule-row">
                    <button type="button" 
                      className={`rule-add-btn ${ruleArray.includes('[') ? 'rule-add-btn-active' : ''}`} 
                      onClick={() => setRuleArray(prev => [...prev, '['])}>
                      {text.deleteFirstChar}
                    </button>
                    <button type="button" 
                      className={`rule-add-btn ${ruleArray.includes(']') ? 'rule-add-btn-active' : ''}`} 
                      onClick={() => setRuleArray(prev => [...prev, ']'])}>
                      {text.deleteLastChar}
                    </button>
                    <label> (eg abc → bc / ab)</label>
                  </div>

                  {/* 第十三行：删除位置n的字符 */}
                  <div className="rule-row">
                    <button type="button" 
                      className={`rule-add-btn ${ruleArray.some(r => r.startsWith('D')) ? 'rule-add-btn-active' : ''}`} 
                      onClick={() => {
                        const n = deletePosition || '1';
                        setRuleArray(prev => [...prev, `D${n}`]);
                      }}>
                      {text.deleteCharAt}
                    </button>
                    <input
                      type="number"
                      min="1"
                      value={deletePosition}
                      onChange={(e) => setDeletePosition(e.target.value)}
                      className="nth-input"
                      placeholder={text.position}
                    />
                    <label> (eg D2, abc → ac)</label>
                  </div>

                  {/* 第十四行：提取位置n开始的M个字符 */}
                  <div className="rule-row">
                    <button type="button" 
                      className={`rule-add-btn ${ruleArray.some(r => r.startsWith('x')) ? 'rule-add-btn-active' : ''}`} 
                      onClick={() => {
                        const n = extractStartPos || '1';
                        const m = extractLength || '2';
                        setRuleArray(prev => [...prev, `x${n}${m}`]);
                      }}>
                      {text.extractChars}
                    </button>
                    <input
                      type="number"
                      min="1"
                      value={extractStartPos}
                      onChange={(e) => setExtractStartPos(e.target.value)}
                      className="nth-input"
                      placeholder={text.position}
                    />
                    <input
                      type="number"
                      min="1"
                      value={extractLength}
                      onChange={(e) => setExtractLength(e.target.value)}
                      className="nth-input"
                      placeholder={text.length}
                    />
                    <label> (eg x23, abcde → bcd)</label>
                  </div>

                  {/* 第十五行：从位置n开始删除M个字符 */}
                  <div className="rule-row">
                    <button type="button" 
                      className={`rule-add-btn ${ruleArray.some(r => r.startsWith('O')) ? 'rule-add-btn-active' : ''}`} 
                      onClick={() => {
                        const n = deleteStartPos || '1';
                        const m = deleteLength || '2';
                        setRuleArray(prev => [...prev, `O${n}${m}`]);
                      }}>
                      {text.deleteCharsFrom}
                    </button>
                    <input
                      type="number"
                      min="1"
                      value={deleteStartPos}
                      onChange={(e) => setDeleteStartPos(e.target.value)}
                      className="nth-input"
                      placeholder={text.position}
                    />
                    <input
                      type="number"
                      min="1"
                      value={deleteLength}
                      onChange={(e) => setDeleteLength(e.target.value)}
                      className="nth-input"
                      placeholder={text.length}
                    />
                    <label> (eg O22, abcde → ae)</label>
                  </div>

                  {/* 第十六行：删除所有x字符 */}
                  <div className="rule-row">
                    <button type="button" 
                      className={`rule-add-btn ${ruleArray.some(r => r.startsWith('@')) ? 'rule-add-btn-active' : ''}`} 
                      onClick={() => {
                        const x = deleteAllChar || 'a';
                        setRuleArray(prev => [...prev, `@${x}`]);
                      }}>
                      {text.deleteAllChar}
                    </button>
                    <input
                      type="text"
                      maxLength={1}
                      value={deleteAllChar}
                      onChange={(e) => setDeleteAllChar(e.target.value.slice(0, 1))}
                      className="nth-input"
                      placeholder={text.char}
                    />
                    <label> (eg @a, banana → bnn)</label>
                  </div>
                </div>
              </div>
              </div>
                  {/* 高级规则区域 */}
                  <div className="rule-section" style={{ marginTop: '20px' }}>
                    <h3>{text.advancedRules}</h3>
                    <div className="rule-options">
                      {/* 第一行：忽略长度大于N的密码 / 忽略长度小于N的密码 */}
                      <div className="rule-row">
                        <button type="button" 
                          className={`rule-add-btn ${advancedArray.some(r => r.startsWith('<')) ? 'rule-add-btn-active' : ''}`} 
                          onClick={() => {
                            const n = advLengthN || '8';
                            setAdvancedArray(prev => [...prev, `<${n}`]);
                          }}>
                          {text.ignoreLongerLength}
                        </button>
                        <input
                          type="number"
                          min="0"
                          value={advLengthN}
                          onChange={(e) => setAdvLengthN(e.target.value)}
                          className="nth-input"
                          placeholder={text.number}
                        />
                      </div>

                      {/* 第二行：只使用长度等于N的密码 */}
                      <div className="rule-row">
                        <button type="button" 
                          className={`rule-add-btn ${advancedArray.some(r => r.startsWith('>')) ? 'rule-add-btn-active' : ''}`} 
                          onClick={() => {
                            const n = advLengthN2 || '1';
                            setAdvancedArray(prev => [...prev, `>${n}`]);
                          }}>
                          {text.ignoreShorterLength}
                        </button>
                        <input
                          type="number"
                          min="1"
                          value={advLengthN2}
                          onChange={(e) => setAdvLengthN2(e.target.value)}
                          className="nth-input"
                          placeholder={text.number}
                        />
                      </div>

                      {/* 第三行：忽略长度小于N的密码（_） */}
                      <div className="rule-row">
                        <button type="button" 
                          className={`rule-add-btn ${advancedArray.some(r => r.startsWith('_')) ? 'rule-add-btn-active' : ''}`} 
                          onClick={() => {
                            const n = advLengthN3 || '8';
                            setAdvancedArray(prev => [...prev, `_${n}`]);
                          }}>
                          {text.onlyLengthEqual}
                        </button>
                        <input
                          type="number"
                          min="1"
                          value={advLengthN3}
                          onChange={(e) => setAdvLengthN3(e.target.value)}
                          className="nth-input"
                          placeholder={text.number}
                        />
                      </div>

                      {/* 第四行：忽略不包含X的密码 */}
                      <div className="rule-row">
                        <button type="button" 
                          className={`rule-add-btn ${advancedArray.some(r => r.startsWith('/')) ? 'rule-add-btn-active' : ''}`} 
                          onClick={() => {
                            const x = advFilterChar || 'a';
                            setAdvancedArray(prev => [...prev, `/${x}`]);
                          }}>
                          {text.ignoreWithoutChar}
                        </button>
                        <input
                          type="text"
                          maxLength={1}
                          value={advFilterChar}
                          onChange={(e) => setAdvFilterChar(e.target.value.slice(0, 1))}
                          className="nth-input"
                          placeholder={text.char}
                        />
                      </div>

                      {/* 第五行：忽略开头不是X的密码 */}
                      <div className="rule-row">
                        <button type="button" 
                          className={`rule-add-btn ${advancedArray.some(r => r.startsWith('(')) ? 'rule-add-btn-active' : ''}`} 
                          onClick={() => {
                            const x = advStartChar || 'a';
                            setAdvancedArray(prev => [...prev, `(${x}`]);
                          }}>
                          {text.ignoreNotStartWith}
                        </button>
                        <input
                          type="text"
                          maxLength={1}
                          value={advStartChar}
                          onChange={(e) => setAdvStartChar(e.target.value.slice(0, 1))}
                          className="nth-input"
                          placeholder={text.char}
                        />
                      </div>

                      {/* 第六行：忽略结尾不是X的密码 */}
                      <div className="rule-row">
                        <button type="button" 
                          className={`rule-add-btn ${advancedArray.some(r => r.startsWith(')')) ? 'rule-add-btn-active' : ''}`} 
                          onClick={() => {
                            const x = advEndChar || 'a';
                            setAdvancedArray(prev => [...prev, `)${x}`]);
                          }}>
                          {text.ignoreNotEndWith}
                        </button>
                        <input
                          type="text"
                          maxLength={1}
                          value={advEndChar}
                          onChange={(e) => setAdvEndChar(e.target.value.slice(0, 1))}
                          className="nth-input"
                          placeholder={text.char}
                        />
                      </div>
                    </div>
                  </div>
            </div>
            {/* 预览和应用区域 */}
            <div className="modal-footer">
              <div className="rule-preview">
                <span className="preview-label">
                  {text.previewRule}
                  {(ruleArray.length > 0 || advancedArray.length > 0) && (
                    <>
                      <button type="button" className="rule-clear-btn" onClick={deleteLastRule}>
                        {text.delete}
                      </button>
                      <button type="button" className="rule-clear-btn" onClick={clearPreview}>
                        {text.clear}
                      </button>
                    </>
                  )}
                </span>
                  <div className="preview-content">
                  <span className="preview-value">
                    {(() => {
                      const adv = advancedArray.join(' ');
                      const norm = ruleArray.join('');
                      if (adv && norm) return `${adv} ${norm}`;
                      return adv || norm || '-';
                    })()}
                  </span>
                </div>
              </div>
              <button
                type="button"
                onClick={applyRule}
                disabled={ruleArray.length === 0 && advancedArray.length === 0}
                className="primary-button"
              >
                {text.applyRule}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}


function ResourcePickerModal({ 
  isOpen, 
  onClose,
  userDictionaries,
  customResources,
  resourceKind, 
  text,
  onUseCustomResource,
  onUseUserDictionary,
  attackMode,
  ruleType,
  groups
}: {
  isOpen: boolean;
  onClose: () => void;
  resources: ResourceInfo[];
  userDictionaries: UserDictionary[];
  customResources: CustomResource[];
  resourceKind: "dictionary" | "rule" | "mask" | "charset" | "template";
  text: UiText;
  onUseResource: (resource: ResourceInfo) => void;
  onUseCustomResource: (resource: CustomResource) => void;
  onUseUserDictionary: (dict: UserDictionary) => void;
  attackMode: AttackMode;
  ruleType?: "left" | "right";
  groups?: { id: string; name: string; resourceIds: string[]; expanded: boolean }[];
}) {
  if (!isOpen) return null;

  const [preview, setPreview] = useState<FilePreviewResponse | null>(null);
  const [previewName, setPreviewName] = useState("");
  const [localGroups, setLocalGroups] = useState<{ id: string; name: string; resourceIds: string[]; expanded: boolean }[]>(groups || []);
  
  const getDisplayItems = () => {
    if (resourceKind === "dictionary") {
      const userDicts = userDictionaries.map(dict => ({
        type: "user" as const,
        dict: dict
      }));
      
      const customDicts = customResources
        .filter(r => r.type === "dictionary" && r.path)
        .map(resource => ({
          type: "custom" as const,
          resource: resource
        }))
        .sort((a, b) => (a.resource.sortOrder || 0) - (b.resource.sortOrder || 0));  // ✅ 按 sortOrder 排序

      return [...customDicts, ...userDicts];
    } else if (resourceKind === "mask") {
      const isHybridMode = attackMode === 6 || attackMode === 7;
      
      const customMasks = customResources
        .filter(r => r.type === "mask" && (!isHybridMode || !r.path))
        .map(resource => ({
          type: "custom" as const,
          resource: resource
        }))
        .sort((a, b) => (a.resource.sortOrder || 0) - (b.resource.sortOrder || 0));  // ✅ 按 sortOrder 排序
      
      return [...customMasks];
    } else if (resourceKind === "charset") {
      const customCharsets = customResources
        .filter(r => r.type === "charset")
        .map(resource => ({
          type: "custom" as const,
          resource: resource
        }))
        .sort((a, b) => (a.resource.sortOrder || 0) - (b.resource.sortOrder || 0));  // ✅ 按 sortOrder 排序
      
      return [...customCharsets];
    } else if (resourceKind === "template") {
      const customTemplates = customResources
        .filter(r => r.type === "template")
        .map(resource => ({
          type: "custom" as const,
          resource: resource
        }))
        .sort((a, b) => (a.resource.sortOrder || 0) - (b.resource.sortOrder || 0));  // ✅ 按 sortOrder 排序
      
      return [...customTemplates];
    } else {
      const customRules = customResources
        .filter(r => {
          if (r.type !== "rule") return false;
          if (ruleType === "left") {
            return !!r.ruleValue && r.ruleType === "left";
          }
          if (ruleType === "right") {
            return !!r.ruleValue && r.ruleType === "right";
          }
          return !!r.path;
        })
        .map(resource => ({
          type: "custom" as const,
          resource: resource
        }))
        .sort((a, b) => (a.resource.sortOrder || 0) - (b.resource.sortOrder || 0));  // ✅ 按 sortOrder 排序
      
      return [...customRules];
    }
  };
  
  const getItemId = (item: typeof items[number]) => {
    return item.type === "custom" ? item.resource.id : item.dict.path;
  };

  const getItemsInGroup = (groupId: string) => {
    const group = localGroups.find(g => g.id === groupId);
    if (!group) return [];
    
    // 创建一个映射表，便于快速查找
    const itemMap = new Map<string, typeof items[number]>();
    items.forEach(item => {
      itemMap.set(getItemId(item), item);
    });
    
    // 按照 group.resourceIds 的顺序返回资源，确保排序操作生效
    return group.resourceIds
      .map(id => itemMap.get(id))
      .filter((item): item is typeof items[number] => item !== undefined);
  };

  const getUngroupedItems = () => {
    if (localGroups.length === 0) {
      // 没有分组时，直接返回 items（已在 getDisplayItems 中按 sortOrder 排序）
      // 保持与自定义资源页面一致的排序逻辑：自定义资源按 sortOrder，用户字典追加在后面
      return items;
    }
    
    const groupedIds = new Set(localGroups.flatMap(g => g.resourceIds));
    const ungrouped = items.filter(item => !groupedIds.has(getItemId(item)));
    
    // 直接返回过滤后的列表（已在 getDisplayItems 中按 sortOrder 排序）
    // 保持与自定义资源页面一致的排序逻辑
    return ungrouped;
  };

  const toggleGroup = (groupId: string) => {
    setLocalGroups(prev => prev.map(g => 
      g.id === groupId ? { ...g, expanded: !g.expanded } : g
    ));
  };

  const items = getDisplayItems();
  
  const handleUse = (item: typeof items[number]) => {
    if (item.type === "user") {
      onUseUserDictionary(item.dict);  // 直接传递完整的 UserDictionary
    } else if (item.type === "custom") {
      onUseCustomResource(item.resource);  // 直接传递完整的 CustomResource
    }
    onClose();
  };

  const handlePreview = async (item: typeof items[number]) => {
    let name = "";
    let path = "";
    
    if (item.type === "user") {
      name = item.dict.name;
      path = item.dict.path;
    } else if (item.type === "custom" && item.resource.path) {
      name = item.resource.name;
      path = item.resource.path;
    }
    
    if (path) {
      try {
        setPreviewName(name);
        setPreview(await invoke<FilePreviewResponse>("preview_text_file", { path, allowFull: item.type === "user" }));
      } catch (err) {
        setPreviewName(name);
        setPreview(null);
      }
    }
  };
  
  // 渲染资源项
  const renderResourceItem = (item: typeof items[number], isInGroup = false) => {
    const isValid = item.type === "user" ? item.dict.isValid !== false : item.resource.isValid !== false;
    return (
    <div key={getItemId(item)} className={`resource-row${isInGroup ? " in-group" : ""}${!isValid ? " invalid" : ""}`}>
      <div>
        <strong>{!isValid && <span className="resource-invalid">({text.resourceInvalid})</span>}{item.type === "user" ? item.dict.name : item.resource.name}</strong>
        <span>
          {item.type === "user" 
            ? `${text.userDictionaries} · ${formatSize(item.dict.size)} · ${shortPath(item.dict.path)}`
            : `${customResourceTypeLabel(item.resource, text)} · ${customResourceValue(item.resource)}`
          }
        </span>
        <em>
          {item.type === "user" 
            ? text.resourceDictionaryHelp 
            : item.resource.description || (item.resource.type === "mask" ? text.resourceMaskFileHelp : text.templateHint)}
        </em>
      </div>
      <div className="resource-actions">
        {(item.type === "user" || (item.type === "custom" && item.resource.path)) && (
          <button type="button" onClick={() => handlePreview(item)}>{text.preview}</button>
        )}
        <button type="button" onClick={() => handleUse(item)}>{text.use}</button>
      </div>
    </div>
  )};

  // 渲染分组
  const renderGroups = () => {
    if (localGroups.length === 0) return null;

    return localGroups.map(group => {
      const groupItems = getItemsInGroup(group.id);
      if (groupItems.length === 0) return null;

      return (
        <div key={group.id} className={`resource-group${group.expanded ? '' : ' collapsed'}`}>
          <div 
            className="group-header" 
            onClick={() => toggleGroup(group.id)}
          >
            <button type="button" className="group-toggle" onClick={(e) => {
              e.stopPropagation();
              toggleGroup(group.id);
            }}>
              {group.expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </button>
            <span className="group-name">{group.name}</span>
            <span className="group-count">({groupItems.length})</span>
          </div>
          <div className="group-content">
            {groupItems.map(item => renderResourceItem(item, true))}
          </div>
        </div>
      );
    });
  };

  return (
    <>
      {/* backdrop */}
      <div className="modal-backdrop" onClick={onClose}>
        {/* modal content */}
        <section className="resource-picker-modal" onClick={e => e.stopPropagation()}>
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Resources</p>
              <h2>
                {resourceKind === "dictionary" ? text.userDictionaries : 
                resourceKind === "rule" ? text.rulesFile : 
                resourceKind === "template" ? text.templateAttack : text.mask}
              </h2>
            </div>
            <button className="icon-button" type="button" onClick={onClose}><X size={15} /></button>
          </div>
          <div className="resource-list compact">
            {renderGroups()}
            {getUngroupedItems().length > 0 ? (
              getUngroupedItems().map(item => renderResourceItem(item, false))
            ) : localGroups.length > 0 && items.length === 0 ? (
              <div className="empty-state">
                {resourceKind === "dictionary" ? text.noUserDictionaries : 
                 resourceKind === "mask" ? text.noCustomMasks : text.noRuleResources}
              </div>
            ) : null}
            {localGroups.length === 0 && items.length === 0 && (
              <div className="empty-state">
                {resourceKind === "dictionary" ? text.noUserDictionaries : 
                 resourceKind === "mask" ? text.noCustomMasks : text.noRuleResources}
              </div>
            )}
          </div>
          {/* 预览模态框 */}
          {preview && (
            <>
              <div className="preview-backdrop" onClick={() => setPreview(null)}></div>
              <div className="preview-panel">
                <div className="panel-heading">
                  <div>
                    <p className="eyebrow">{text.resourcePreviewTitle}</p>
                    <h2>{previewName}</h2>
                  </div>
                  <button className="icon-button" type="button" onClick={() => setPreview(null)}><X size={15} /></button>
                </div>
                <pre className="preview-output">{preview.content || text.previewEmpty}</pre>
              </div>
            </>
          )}
        </section>
      </div>
    </>
  );
}

// 预设选择器模态框
function PresetPickerModal({
  isOpen,
  onClose,
  presets,
  presetGroups,
  text,
  onUsePreset,
  onUseAllPresets
}: {
  isOpen: boolean;
  onClose: () => void;
  presets: PresetConfig[];
  presetGroups: PresetGroup[];
  text: UiText;
  onUsePreset: (preset: PresetConfig) => void;
  onUseAllPresets?: (presets: PresetConfig[]) => void;
}) {
  if (!isOpen) return null;

  const [localGroups, setLocalGroups] = useState<PresetGroup[]>(presetGroups || []);

  // 获取未分组的预设
  const getUngroupedPresets = () => {
    if (localGroups.length === 0) {
      return presets;
    }
    const groupedIds = new Set(localGroups.flatMap(g => g.presetIds));
    return presets.filter(p => !groupedIds.has(p.id));
  };

  // 获取分组中的预设（按分组内的顺序）
  const getPresetsInGroup = (groupId: string) => {
    const group = localGroups.find(g => g.id === groupId);
    if (!group) return [];
    return group.presetIds
      .map(id => presets.find(p => p.id === id))
      .filter((p): p is PresetConfig => p !== undefined);
  };

  // 切换分组展开状态
  const toggleGroup = (groupId: string) => {
    setLocalGroups(prev => prev.map(g =>
      g.id === groupId ? { ...g, expanded: !g.expanded } : g
    ));
  };

  // 判断是否中文
  const isZh = text.settingsTitle === "设置";

  // 渲染预设项
  const renderPresetItem = (preset: PresetConfig, isInGroup = false) => {
    // 如果没有缓存的详情信息，临时生成（兼容旧数据）
    const detail = preset.detailDisplay || generatePresetDetail(preset, text, isZh);
    const isValid = preset.isValid !== false;
    return (
      <div key={preset.id} className={`resource-row${isInGroup ? " in-group" : ""} ${!isValid ? "invalid" : ""}`}>
        <div>
          <strong>{!isValid && <span className="resource-invalid">({text.resourceInvalid})</span>}{preset.name}</strong>
          <span>
            {attackModeLabel(preset.attackMode, text)} · {detail}
          </span>
          <em>{preset.description || text.noDescription}</em>
        </div>
        <div className="resource-actions">
          <button type="button" onClick={() => {
            onUsePreset(preset);
            onClose();
          }}>{text.use}</button>
        </div>
      </div>
    );
  };

  // 渲染分组
  const renderGroups = () => {
    if (localGroups.length === 0) return null;

    return localGroups.map(group => {
      const groupPresets = getPresetsInGroup(group.id);
      if (groupPresets.length === 0) return null;

      return (
        <div key={group.id} className={`resource-group${group.expanded ? '' : ' collapsed'}`}>
          <div
            className="group-header"
            onClick={() => toggleGroup(group.id)}
          >
            <button type="button" className="group-toggle" onClick={(e) => {
              e.stopPropagation();
              toggleGroup(group.id);
            }}>
              {group.expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </button>
            <span className="group-name">{group.name}</span>
            <span className="group-count">({groupPresets.length})</span>
            <div className="group-actions">
              <button 
                type="button" 
                className="group-useall" 
                onClick={(e) => {
                  e.stopPropagation();
                  if (onUseAllPresets) {
                    onUseAllPresets(groupPresets);
                    onClose();
                  }
                }}
                disabled={groupPresets.length === 0}
              >
                <span>{isZh ? "使用全部" : "Use All"}</span>
              </button>
            </div>
          </div>
          <div className="group-content">
            {groupPresets.map(preset => renderPresetItem(preset, true))}
          </div>
        </div>
      );
    });
  };

  return (
    <>
      {/* backdrop */}
      <div className="modal-backdrop" onClick={onClose}>
        {/* modal content */}
        <section className="resource-picker-modal" onClick={e => e.stopPropagation()}>
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Custom Presets</p>
              <h2>{text.presets}</h2>
            </div>
            <button className="icon-button" type="button" onClick={onClose}><X size={15} /></button>
          </div>
          <div className="resource-list compact">
            {renderGroups()}
            {getUngroupedPresets().length > 0 ? (
              getUngroupedPresets().map(preset => renderPresetItem(preset, false))
            ) : localGroups.length > 0 && presets.length === 0 ? (
              <div className="empty-state">
                {text.noPresets}
              </div>
            ) : null}
            {localGroups.length === 0 && presets.length === 0 && (
              <div className="empty-state">
                {text.noPresets}
              </div>
            )}
          </div>
        </section>
      </div>
    </>
  );
}


function MaskEstimateCard({ estimate, text }: { estimate: MaskEstimate | null; text: UiText }) {
  if (!estimate) return null;
  const candidates = estimate.candidates ? formatBigInt(estimate.candidates) : "--";
  const speed = estimate.speedHps ? `${formatNumber(Math.round(estimate.speedHps))} H/s` : text.maskEstimateUnknown;
  const time = estimate.estimatedSeconds !== undefined ? formatDuration(estimate.estimatedSeconds) : "--";
  const long = shouldConfirmLongTask(estimate);
  return (
    <div className={long ? "mask-estimate-card warn" : "mask-estimate-card"}>
      <div className="line-title"><Activity size={14} /><span>{text.maskEstimate}</span>{long && <strong>{text.taskMayRunLong}</strong>}</div>
      <div className="mask-estimate-grid">
        <span>{text.maskCandidates}<strong>{candidates}</strong></span>
        <span>{text.maskEstimateSpeed}<strong>{speed}</strong></span>
        <span>{text.maskEstimatedTime}<strong>{time}</strong></span>
      </div>
      {(estimate.error || estimate.warning) && <em>{estimate.error || estimate.warning}</em>}
    </div>
  );
}

function HashSuggestionPanel({ suggestions, identifyModes, identifyRaw, identifyRunning, text, onApply, onIdentify }: {
  suggestions: HashModeSuggestion[];
  identifyModes: HashModeInfo[];
  identifyRaw: string;
  identifyRunning: boolean;
  text: UiText;
  onApply: (mode: string) => void;
  onIdentify: () => void;
}) {
  return (
    <div className="hash-suggestion-panel">
      <div className="line-title">
        <Sparkles size={14} />
        <span>{text.hashRecommendTitle}</span>
        <strong>
          {text.hashRecommendHint}
          {!suggestions.length && ` ${text.hashRecommendEmpty}`}
        </strong>
        <button type="button" onClick={onIdentify} disabled={identifyRunning}>
          {identifyRunning ? text.hashIdentifyRunning : text.hashOfficialIdentify}
        </button>
      </div>
            {suggestions.length ? (
              <div className="hash-suggestion-list">
                {suggestions.slice(0, 5).map((suggestion) => (
                  <button type="button" key={`${suggestion.mode}-${suggestion.name}`} onClick={() => onApply(suggestion.mode)}>
                    <strong>-m {suggestion.mode}</strong>
                    <span>{suggestion.name}</span>
                    <em>{confidenceLabel(suggestion.confidence, text)} · {suggestion.reason}</em>
                    <b>{text.applyRecommendation}</b>
                  </button>
                ))}
              </div>
            ) : null}
      {(identifyModes.length > 0 || identifyRaw) && (
        <div className="official-identify-list">
          <div className="line-title"><span>{text.hashOfficialIdentify}</span><strong>{identifyModes.length ? `${identifyModes.length}` : text.hashIdentifyEmpty}</strong></div>
          {identifyModes.slice(0, 5).map((mode) => (
            <button type="button" key={`identify-${mode.mode}`} onClick={() => onApply(String(mode.mode))}>
              <strong>-m {mode.mode}</strong><span>{mode.name}</span><em>{mode.category}</em><b>{text.applyRecommendation}</b>
            </button>
          ))}
          {!identifyModes.length && <pre>{identifyRaw}</pre>}
        </div>
      )}
    </div>
  );
}
function CustomCharsetEditor({ 
  values, 
  onChange, 
  text, 
  attackMode, 
  enabled, 
  onToggle, 
  onOpenResourcePicker, 
  charsetFiles, 
  onClearCharsetFile, 
  disabled = false  // 设置默认值
}: {
  values: string[];
  onChange: (slot: 1 | 2 | 3 | 4, value: string) => void;
  text: UiText;
  attackMode: AttackMode;
  enabled: boolean;
  onToggle: (enabled: boolean) => void;
  onOpenResourcePicker?: () => void;
  charsetFiles?: string[];
  onClearCharsetFile?: (slot: 1 | 2 | 3 | 4) => void;
  disabled?: boolean;
}) {
  const isHybridMode = attackMode === 6 || attackMode === 7;
  
  return (
    <div className="custom-charset-card">
      <div className="line-title">
        <label className="checkbox-label">
          <input type="checkbox" checked={enabled} onChange={(e) => onToggle(e.target.checked)} disabled={disabled}/>
          <span>{text.customCharset}</span>
        </label>
        {!isHybridMode && <strong>{text.charsetHint}</strong>}
        {onOpenResourcePicker && (
          <button type="button" onClick={onOpenResourcePicker}>{text.useResource}</button>
        )}
      </div>
      {enabled && (
        <div className={`charset-grid ${attackMode === 6 || attackMode === 7 ? "two-columns" : ""}`}>
          {[1, 2, 3, 4].map((slot) => {
            const file = charsetFiles?.[slot - 1];
            return (
              <div key={slot} className="charset-slot-wrapper">
                <label className="field">
                  <span>?{slot}</span>
                  <input value={values[slot - 1] ?? ""} onChange={(event) => onChange(slot as 1 | 2 | 3 | 4, event.currentTarget.value)} placeholder={slot === 1 ? "?l?d" : ""} spellCheck={false} />
                </label>
                {file && (
                  <span className="path-pill" title={file}>
                    <span className="path-pill-text">{shortPath(file)}</span>
                    <button type="button" onClick={() => onClearCharsetFile?.(slot as 1 | 2 | 3 | 4)}>
                      <X size={12} />
                    </button>
                  </span>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function DevicePerformancePanel(props: {
  backendInfo: Record<string, unknown> | null;
  backendRaw: string;
  latestStatus: Record<string, unknown> | null;
  scanState: "idle" | "scanning" | "done" | "error";
  onRefreshDevices: () => void;
  text: UiText;
  language: Language;
}) {
  const zh = props.language === "zh";
  const devices = extractStatusDevices(props.latestStatus, zh);
  const backendDevices = extractBackendDevices(props.backendInfo, props.backendRaw);
  const backendLines = props.backendRaw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).slice(0, 4);
  const scanMessage = props.scanState === "scanning"
    ? props.text.deviceScanning
    : props.scanState === "done"
      ? props.text.deviceScanDone
      : props.scanState === "error"
        ? props.text.deviceScanFailed
        : props.text.deviceScanReady;

  return (
    <section className="device-performance-panel">
      <div className="device-panel-head">
        <div>
          <p className="eyebrow">Device</p>
          <h2>{props.text.deviceControl}</h2>
          {/*<span>{props.text.deviceControlHint}</span>*/}
        </div>
        <button className="ghost-button" type="button" onClick={props.onRefreshDevices} disabled={props.scanState === "scanning"}><Sparkles size={15} />{props.scanState === "scanning" ? props.text.deviceScanning : props.text.scanDevices}</button>
      </div>

      <div className="device-telemetry-grid">
        {devices.length ? devices.map((device, index) => (
          <div className="telemetry-card" key={`${device.name}-${index}`}>
            <div className="telemetry-title"><strong>{device.name || `${props.text.gpuDevice} ${index + 1}`}</strong><span>{device.type || props.text.deviceAuto}</span></div>
            <Metric icon={<Zap size={14} />} label={props.text.speed} value={device.speed || "--"} />
            <Metric icon={<Thermometer size={14} />} label={props.text.temperature} value={device.temperature || "--"} />
            <Metric icon={<Activity size={14} />} label={props.text.utilization} value={device.utilization || "--"} />
            <Metric icon={<Cpu size={14} />} label={props.text.memory} value={device.memory || "--"} />
          </div>
        )) : (
          <div className="telemetry-empty">{props.text.noDeviceStatus}</div>
        )}
        <div className="backend-info-card">
          <div className="line-title"><ShieldCheck size={15} /><span>{props.text.backendDeviceInfo}</span></div>
          <em className={props.scanState === "error" ? "scan-state error" : "scan-state"}>{scanMessage}</em>
          {backendDevices.length ? (
            <div className="backend-device-list">
              {backendDevices.map((device, index) => (
                <div className="backend-device-card" key={`${device.name}-${index}`}>
                  <div className="backend-device-head">
                    <strong>{device.name}</strong>
                    <span>{device.backend || props.text.deviceBackend}</span>
                  </div>
                  <div className="backend-chip-row">
                    {device.id && <em>{props.text.deviceIdLabel}: -d {device.id}</em>}
                    {device.vendor && <em>{props.text.deviceVendor}: {device.vendor}</em>}
                    {device.type && <em>{device.type}</em>}
                    {device.memory && <em>{props.text.deviceMemory}: {device.memory}</em>}
                    {device.processor && <em>{props.text.deviceProcessor}: {device.processor}</em>}
                  </div>
                </div>
              ))}
            </div>
          ) : backendLines.length ? (
            <details className="backend-raw-details">
              <summary>{props.text.backendRawSummary}</summary>
              {backendLines.map((line, index) => <code key={`${line}-${index}`}>{line}</code>)}
            </details>
          ) : <span>{props.text.scanDevices}</span>}
        </div>
      </div>
    </section>
  );
}

function Metric(props: { icon: ReactNode; label: string; value: string }) {
  return <div className="metric">{props.icon}<span>{props.label}</span><strong>{props.value}</strong></div>;
}

function AdvancedSettingsDialog(props: {
  deviceIds: string;
  deviceTypes: string[];
  text: UiText;
  workloadProfile: number;
  optimizedKernel: boolean;
  skipDuplicateHashOnCrack: boolean;
  onDeviceIdsChange: (ids: string) => void;
  onToggleDeviceType: (type: string) => void;
  onWorkloadChange: (value: number) => void;
  onOptimizedKernelChange: (value: boolean) => void;
  onSkipDuplicateHashOnCrackChange: (value: boolean) => void;
  onClose: () => void;
  onCancel: () => void;
  onResetToDefault: () => void;
}) {
  const performance = workloadInfo(props.workloadProfile, props.text);

  return (
    <div className="modal-backdrop" role="presentation">
      <section className="settings-modal" role="dialog" aria-modal="true" aria-label={props.text.deviceControl}>
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Advanced</p>
            <h2>{props.text.advancedSettings}</h2>
          </div>
          <button className="icon-button" type="button" onClick={props.onCancel}><X size={15} /></button>
        </div>

        <div className="device-control-grid">
          <div className="device-type-card">
            <div className="line-title"><Cpu size={15} /><span>{props.text.deviceTypes}</span><strong>-D {props.deviceTypes.length ? props.deviceTypes.join(",") : props.text.deviceAuto}</strong></div>
            <div className="device-toggle-row">
              <button className={props.deviceTypes.includes("1") ? "active" : ""} type="button" onClick={() => props.onToggleDeviceType("1")}><Cpu size={15} />{props.text.cpuDevice}</button>
              <button className={props.deviceTypes.includes("2") ? "active" : ""} type="button" onClick={() => props.onToggleDeviceType("2")}><Zap size={15} />{props.text.gpuDevice}</button>
            </div>
            <label className="field">
              <span>{props.text.deviceIds}</span>
              <input value={props.deviceIds} onChange={(event) => props.onDeviceIdsChange(event.currentTarget.value)} placeholder={props.text.deviceIdsPlaceholder} />
            </label>
          </div>

          <div className="performance-card">
            <div className="line-title"><Activity size={15} /><span>{props.text.performanceMode}</span><strong>-w {props.workloadProfile}</strong></div>
            <div className="performance-mode-row">
              {[1, 2, 3, 4].map((value) => (
                <button className={props.workloadProfile === value ? "active" : ""} key={value} type="button" onClick={() => props.onWorkloadChange(value)}>
                  <strong>{value}</strong>
                  <span>{workloadInfo(value, props.text).label}</span>
                </button>
              ))}
            </div>
            <p>{performance.description}</p>
          </div>

          <div className="kernel-optimization-card">
            <label className="toggle-label">
              <input type="checkbox" checked={props.optimizedKernel} onChange={(e) => props.onOptimizedKernelChange(e.target.checked)} />
              <span className="toggle-slider"></span>
            </label>
            <span className="toggle-text">{props.text.optimizedKernel}</span>
            <span className="toggle-hint">(-O)</span>
          </div>

          <div className="kernel-optimization-card">
            <label className="toggle-label">
              <input type="checkbox" checked={props.skipDuplicateHashOnCrack} onChange={(e) => props.onSkipDuplicateHashOnCrackChange(e.target.checked)} />
              <span className="toggle-slider"></span>
            </label>
            <span className="toggle-text">{props.text.skipDuplicateHashOnCrack}</span>
          </div>
        </div>

        <div className="settings-actions">
          <button className="ghost-button reset-button" type="button" onClick={props.onResetToDefault}>
            <RefreshCcw size={14} />
            {props.text.resetToDefault}
          </button>
          <button className="ghost-button" type="button" onClick={props.onCancel}>{props.text.cancel}</button>
          <button className="primary-button" type="button" onClick={props.onClose}>{props.text.save}</button>
        </div>
      </section>
    </div>
  );
}

function ResourcesTab(props: {
  filteredResources: ResourceInfo[];
  resources: ResourceInfo[];
  query: string;
  setQuery: (query: string) => void;
  resourceTypeFilter: string;
  setResourceTypeFilter: (type: string) => void;
  userDictionaries: UserDictionary[];
  customResources: CustomResource[];
  attackMode: AttackMode;
  importDictionary: () => void;
  removeDictionary: (path: string) => void;
  saveCustomResource: (resource: CustomResource, groupId?: string) => void;
  deleteCustomResource: (resource: CustomResource) => void;
  setCustomResources?: React.Dispatch<React.SetStateAction<CustomResource[]>>;
  updateUserDictionaryName: (path: string, name: string) => void;
  useCustomResource: (resource: CustomResource) => void;
  useResource: (resource: ResourceInfo) => void;
  text: UiText;

  setActiveTab?: (tab: TabKey) => void;
  setAttackMode?: (mode: AttackMode) => void;
  setHashMode?: (mode: string) => void;
  setDictionaryPaths?: (paths: string[]) => void;
  setDictionaryPath?: (path: string) => void;
  setDictionaryPath2?: (path: string) => void;
  setMask?: (mask: string) => void;
  setMaskFile?: (path: string) => void;
  setPrefixMask?: (mask: string) => void;
  setSuffixMask?: (mask: string) => void;
  setUseRules?: (use: boolean) => void;
  setUseLeftRule?: (use: boolean) => void;
  setLeftRule?: (rule: string) => void;
  setUseRightRule?: (use: boolean) => void;
  setRightRule?: (rule: string) => void;
  setCustomCharset?: (slot: 1 | 2 | 3 | 4, value: string) => void;
  setCharsetEnabled?: (enabled: boolean) => void;
  setIncrement?: (increment: boolean) => void;
  setIncrementMin?: (min: string) => void;
  setIncrementMax?: (max: string) => void;
  setRulePaths?: (paths: string[]) => void;
  groups: { id: string; name: string; resourceIds: string[]; expanded: boolean }[];
  setGroups: React.Dispatch<React.SetStateAction<{ id: string; name: string; resourceIds: string[]; expanded: boolean }[]>>;
  manageResources: (CustomResource & { source: "custom" | "user" })[];
  setManageResources: React.Dispatch<React.SetStateAction<(CustomResource & { source: "custom" | "user" })[]>>;
  simpleMode: boolean;
  setSimpleMode: (simple: boolean) => void;
  clearAttackConfig?: () => void;
  presets: PresetConfig[];
  setPresets: React.Dispatch<React.SetStateAction<PresetConfig[]>>;
  presetGroups: PresetGroup[];
  setPresetGroups: React.Dispatch<React.SetStateAction<PresetGroup[]>>;
  onAddToSequence?: () => void;
  showToast?: (message: string) => void;
  addPresetsToSequence?: (presets: PresetConfig[]) => void;
  onRefreshPresets?: () => Promise<void>;
  onRefreshResources?: () => Promise<void>;
  checkPresetFiles?: (preset: PresetConfig) => Promise<boolean>;
  setError?: (error: string) => void;
}) {
  // 添加选项卡状态
  const [activeTab, setActiveTab] = useState<"preset" | "custom" | "builtin">("preset");
  const [selectedPresetGroupId, setSelectedPresetGroupId] = useState<string | null>(null);
  const [selectedPresetId, setSelectedPresetId] = useState<string | null>(null);
  const [showAddPresetDialog, setShowAddPresetDialog] = useState(false);
  const [editingPreset, setEditingPreset] = useState<PresetConfig | null>(null);
  const [isPresetManaging, setIsPresetManaging] = useState(false);
  const [managePresets, setManagePresets] = useState<PresetConfig[]>([]);
  const [selectedPresetIds, setSelectedPresetIds] = useState<string[]>([]);
  const [deletedPresetIds, setDeletedPresetIds] = useState<string[]>([]);
  const [preview, setPreview] = useState<FilePreviewResponse | null>(null);
  const [previewName, setPreviewName] = useState("");
  const [managerOpen, setManagerOpen] = useState(false);
  const [addResourceOpen, setAddResourceOpen] = useState(false);
  const [selectedResourceId, setSelectedResourceId] = useState<string | null>(null);
  const [selectedResourceGroupId, setSelectedResourceGroupId] = useState<string | null>(null);
  const [editingResource, setEditingResource] = useState<CustomResource | null>(null);
  const [isManaging, setIsManaging] = useState(false);      // 是否处于管理模式
  const [selectedIds, setSelectedIds] = useState<string[]>([]);  // 选中的资源ID列表
  const manageResources = props.manageResources;
  const setManageResources = props.setManageResources;
  const [deletedIds, setDeletedIds] = useState<string[]>([]);
  const [showCreateGroupDialog, setShowCreateGroupDialog] = useState(false);
  const [showMoveToGroupDialog, setShowMoveToGroupDialog] = useState(false);
  const groups = props.groups;
  const setGroups = props.setGroups;
  const [newGroupName, setNewGroupName] = useState("");
  const selectAllCheckboxRef = useRef<HTMLInputElement>(null);
  const [editingGroupId, setEditingGroupId] = useState<string | null>(null);
  const [editingGroupName, setEditingGroupName] = useState("");
  const [originalGroups, setOriginalGroups] = useState<{ id: string; name: string; resourceIds: string[]; expanded: boolean }[]>([]);
  const [showCreatePresetGroupDialog, setShowCreatePresetGroupDialog] = useState(false);
  const [showMovePresetToGroupDialog, setShowMovePresetToGroupDialog] = useState(false);
  const presetSelectAllCheckboxRef = useRef<HTMLInputElement>(null);
  const [newPresetGroupName, setNewPresetGroupName] = useState("");
  const [editingPresetGroupId, setEditingPresetGroupId] = useState<string | null>(null);
  const [editingPresetGroupName, setEditingPresetGroupName] = useState("");
  const [originalPresetGroups, setOriginalPresetGroups] = useState<PresetGroup[]>([]);
  const [editingPresetId, setEditingPresetId] = useState<string | null>(null);
  const [editingPresetName, setEditingPresetName] = useState("");
  const [editingResourceId, setEditingResourceId] = useState<string | null>(null);
  const [editingResourceName, setEditingResourceName] = useState("");
  const [ruleEditorTarget, setRuleEditorTarget] = useState<"left" | "right">("left");
  const isZh = props.text.settingsTitle === "设置";

  // 用于缓存正在计算的预设 ID，避免重复计算
  const calculatingPresetIds = useRef<Set<string>>(new Set());

  // 异步计算预设的密码量
  async function estimatePresetCandidates(preset: PresetConfig) {
    // 如果正在计算，跳过
    if (calculatingPresetIds.current.has(preset.id)) return;
    
    calculatingPresetIds.current.add(preset.id);
    
    try {
      let totalCandidates: bigint = 0n;
      let isEstimated = false;
      
      // 模式1：字典组合攻击（字典1 × 字典2）
      if (preset.attackMode === 1 && preset.dictionaryPath && preset.dictionaryPath2) {
        const result1 = await invoke<{ count: number; isEstimated: boolean }>("count_file_lines", { path: preset.dictionaryPath });
        const result2 = await invoke<{ count: number; isEstimated: boolean }>("count_file_lines", { path: preset.dictionaryPath2 });
        totalCandidates = BigInt(result1.count) * BigInt(result2.count);
        isEstimated = result1.isEstimated || result2.isEstimated;
      }
      // 模式6（字典+掩码）/ 模式7（掩码+字典）：字典行数 × 掩码候选数
      else if ((preset.attackMode === 6 || preset.attackMode === 7) && preset.dictionaryPath) {
        // 计算字典行数
        const dictResult = await invoke<{ count: number; isEstimated: boolean }>("count_file_lines", { path: preset.dictionaryPath });
        const dictCandidates = BigInt(dictResult.count);
        isEstimated = dictResult.isEstimated;
        
        // 计算掩码候选数（复用队列页面的 estimateMaskCandidates 函数）
        let maskCandidates: bigint = 1n;
        if (preset.mask) {
          // 将 Record<string, string> 转换为 string[]
          const customCharsetsArray = preset.customCharsets ? Object.values(preset.customCharsets) : undefined;
          const maskResult = estimateMaskCandidates(preset.mask, customCharsetsArray);
          if (maskResult.candidates) {
            maskCandidates = maskResult.candidates;
          } else {
            // 掩码解析失败，无法计算
            calculatingPresetIds.current.delete(preset.id);
            return;
          }
        }
        
        totalCandidates = dictCandidates * maskCandidates;
      }
      // 模式9：模板攻击（字典行数 × 前缀掩码候选数 × 后缀掩码候选数）
      else if (preset.attackMode === 9 && preset.dictionaryPath) {
        // 计算字典行数
        const dictResult = await invoke<{ count: number; isEstimated: boolean }>("count_file_lines", { path: preset.dictionaryPath });
        const dictCandidates = BigInt(dictResult.count);
        isEstimated = dictResult.isEstimated;
        
        // 将 Record<string, string> 转换为 string[]
        const customCharsetsArray = preset.customCharsets ? Object.values(preset.customCharsets) : undefined;
        
        // 计算前缀掩码候选数
        let prefixCandidates: bigint = 1n;
        if (preset.prefixMask) {
          const prefixResult = estimateMaskCandidates(preset.prefixMask, customCharsetsArray);
          if (prefixResult.candidates) {
            prefixCandidates = prefixResult.candidates;
          }
        }
        
        // 计算后缀掩码候选数
        let suffixCandidates: bigint = 1n;
        if (preset.suffixMask) {
          const suffixResult = estimateMaskCandidates(preset.suffixMask, customCharsetsArray);
          if (suffixResult.candidates) {
            suffixCandidates = suffixResult.candidates;
          }
        }
        
        totalCandidates = dictCandidates * prefixCandidates * suffixCandidates;
      }
      // 掩码攻击模式（模式3）使用掩码文件
      else if (preset.attackMode === 3 && preset.maskPath) {
        try {
          const increment = preset.increment;
          const incrementMin = typeof preset.incrementMin === "string" ? parseInt(preset.incrementMin, 10) : preset.incrementMin;
          const incrementMax = typeof preset.incrementMax === "string" ? parseInt(preset.incrementMax, 10) : preset.incrementMax;
          
          const min = (incrementMin === null || incrementMin === undefined || Number.isNaN(incrementMin)) ? 1 : incrementMin;
          const max = (incrementMax === null || incrementMax === undefined || Number.isNaN(incrementMax)) ? 0 : incrementMax;
          
          const result = await invoke<number>("count_mask_file_candidates_with_increment", {
            path: preset.maskPath,
            enableIncrement: increment || false,
            incrementMin: min,
            incrementMax: max,
          });
          totalCandidates = BigInt(result);
        } catch (err) {
          console.error(`Failed to count mask file candidates for preset ${preset.id}:`, err);
        } 
      } else if (preset.attackMode === 3 && preset.mask) {
        // 掩码攻击模式（模式3）使用掩码字符串
        // 将 Record<string, string> 转换为 string[]
        const customCharsetsArray = preset.customCharsets 
          ? [preset.customCharsets["1"] || "", preset.customCharsets["2"] || "", preset.customCharsets["3"] || "", preset.customCharsets["4"] || ""]
          : ["", "", "", ""];
        const maskResult = estimateAttackMask({
          attackMode: 3,
          mask: preset.mask,
          templatePrefixMask: "",
          templateSuffixMask: "",
          customCharsets: customCharsetsArray,
          increment: preset.increment,
          incrementMin: preset.incrementMin,
          incrementMax: preset.incrementMax,
          text: props.text,
        });
        if (maskResult?.candidates) {
          totalCandidates = maskResult?.candidates;
        } else {
          // 掩码解析失败，无法计算
          calculatingPresetIds.current.delete(preset.id);
          return;
        }
      } else {
        // 其他需要字典的攻击模式
        const dictPaths = preset.dictionaryPaths?.length 
          ? preset.dictionaryPaths 
          : (preset.dictionaryPath ? [preset.dictionaryPath] : []);
        
        if (dictPaths.length === 0) {
          calculatingPresetIds.current.delete(preset.id);
          return;
        }
        
        for (const dictPath of dictPaths) {
          // 先从缓存中查找
          const builtinResource = props.filteredResources.find(r => r.kind === "dictionary" && r.path === dictPath);
          if (builtinResource?.candidates != null) {
            totalCandidates += BigInt(builtinResource.candidates);
            if (builtinResource.isEstimated) isEstimated = true;
            continue;
          }
          
          const userDict = props.userDictionaries.find(d => d.path === dictPath);
          if (userDict?.candidates != null) {
            totalCandidates += BigInt(userDict.candidates);
            if (userDict.isEstimated) isEstimated = true;
            continue;
          }
          
          // 如果都找不到，使用后端 API 计算
          try {
            const result = await invoke<{ count: number; isEstimated: boolean }>("count_file_lines", { path: dictPath });
            totalCandidates += BigInt(result.count);
            if (result.isEstimated) isEstimated = true;
          } catch (err) {
            console.error(`Failed to count lines for ${dictPath}:`, err);
          }
        }
      }
      
      // 如果有规则文件，计算规则行数并乘以字典行数（所有规则文件行数相乘）
      if (preset.useRules && preset.rulePaths && preset.rulePaths.length > 0) {
        let totalRuleLines = BigInt(1);
        for (const rulePath of preset.rulePaths) {
          try {
            const result = await invoke<{ count: number; isEstimated: boolean }>("count_rule_file_lines", { path: rulePath });
            totalRuleLines *= BigInt(result.count);
            if (result.isEstimated) isEstimated = true;
          } catch (err) {
            console.error(`Failed to count rule lines for ${rulePath}:`, err);
          }
        }
        totalCandidates *= totalRuleLines;
      }

      // 更新预设的密码量信息和详情显示
      if (totalCandidates > 0n) {
        props.setPresets(prev => prev.map(p => 
          p.id === preset.id 
            ? {
                ...p, 
                candidates: totalCandidates.toString(), 
                isEstimated,
                detailDisplay: generatePresetDetail({...p, candidates: totalCandidates.toString(), isEstimated}, props.text, isZh)
              }
            : p
        ));
      }
    } finally {
      calculatingPresetIds.current.delete(preset.id);
    }
  }

  // 使用 useEffect 在预设列表变化时触发计算
  useEffect(() => {
    props.presets.forEach(preset => {
      // 如果还没有计算过密码量，并且是需要字典的攻击模式
      if (!preset.candidates && [0, 1, 3, 6, 7, 9].includes(preset.attackMode)) {
        void estimatePresetCandidates(preset);
      }
    });
  }, [props.presets, props.filteredResources, props.userDictionaries]);

  useEffect(() => {
    if (selectAllCheckboxRef.current) {
      selectAllCheckboxRef.current.indeterminate = getSelectAllState() === "indeterminate";
    }
  }, [selectedIds, props.query, props.resourceTypeFilter]);

  useEffect(() => {
      // 自动保存时禁止清空，必须通过管理模式主动清空
      const presetsJson = JSON.stringify(props.presets);
      const isEmpty = presetsJson === '[]';
      if (isEmpty) {
          // 空数组不保存（避免意外清空），除非通过管理模式
          return;
      }
      invoke("write_presets_file", { presetsJson, allowEmpty: false })
          .catch(console.error);
  }, [props.presets]);

  useEffect(() => {
    invoke("write_preset_groups_file", { groupsJson: JSON.stringify(props.presetGroups) })
      .catch(console.error);
  }, [props.presetGroups]);

  useEffect(() => {
    props.setPresets(prev => prev.map(p => ({
      ...p,
      detailDisplay: p.candidates 
        ? generatePresetDetail(p, props.text, isZh) 
        : undefined
    })));
  }, [props.text, isZh]);

  // 攻击模式转类型字符串（用于CSS类名）
  function attackModeToType(mode: AttackMode): string {
    switch (mode) {
      case 0: return "dictionary";
      case 1: return "dictionary";
      case 3: return "mask";
      case 6: return "mask";
      case 7: return "mask";
      case 9: return "template";
      default: return "dictionary";
    }
  }

  // 使用预设 - 跳转到任务页面并设置参数
  async function usePreset(preset: PresetConfig) {
    // 收集预设引用的所有文件路径（不包括 leftRule 和 rightRule，它们是字符串规则）
    const filePathSet = new Set<string>();
    if (preset.dictionaryPath) filePathSet.add(preset.dictionaryPath);
    if (preset.dictionaryPath2) filePathSet.add(preset.dictionaryPath2);
    if (preset.dictionaryPaths) preset.dictionaryPaths.forEach(p => filePathSet.add(p));
    if (preset.maskPath) filePathSet.add(preset.maskPath);
    if (preset.rulePaths) preset.rulePaths.forEach(p => filePathSet.add(p));
    
    // 检查文件是否存在
    const missingFiles = await Promise.all(
      Array.from(filePathSet).map(async path => ({ path, exists: await invoke('check_file_exists', { path }) }))
    ).then(results => results.filter(r => !r.exists).map(r => r.path));
    
    // 如果有文件不存在，显示错误提示并返回
    if (missingFiles.length > 0) {
      const errorMsg = isZh
        ? `预设引用的文件不存在，无法使用：\n${missingFiles.join('\n')}`
        : `The preset references missing files, cannot apply:\n${missingFiles.join('\n')}`;
      props.setError?.(errorMsg);
      return;
    }

    props.clearAttackConfig?.();
    // 切换到任务配置页面
    props.setActiveTab?.("config");
    
    // 设置攻击模式
    props.setAttackMode?.(preset.attackMode);
    
    // 设置其他配置
    if (preset.hashMode) props.setHashMode?.(preset.hashMode);
    if (preset.dictionaryPaths) props.setDictionaryPaths?.(preset.dictionaryPaths);
    if (preset.dictionaryPath) props.setDictionaryPath?.(preset.dictionaryPath);
    if (preset.dictionaryPath2) props.setDictionaryPath2?.(preset.dictionaryPath2);
    if (preset.mask) props.setMask?.(preset.mask);
    if (preset.maskPath) props.setMaskFile?.(preset.maskPath);
    if (preset.prefixMask) props.setPrefixMask?.(preset.prefixMask);
    if (preset.suffixMask) props.setSuffixMask?.(preset.suffixMask);
    if (preset.useLeftRule !== undefined) props.setUseLeftRule?.(preset.useLeftRule);
    if (preset.leftRule) props.setLeftRule?.(preset.leftRule);
    if (preset.useRightRule !== undefined) props.setUseRightRule?.(preset.useRightRule);
    if (preset.rightRule) props.setRightRule?.(preset.rightRule);
    if (preset.customCharsets) {
      props.setCharsetEnabled?.(true);
      Object.entries(preset.customCharsets).forEach(([slot, value]) => {
        props.setCustomCharset?.(Number(slot) as 1 | 2 | 3 | 4, value);
      });
    }
    if (preset.rulePaths && preset.rulePaths.length > 0) {
      props.setUseRules?.(true);
      props.setRulePaths?.(preset.rulePaths);
    }
    if (preset.increment !== undefined) props.setIncrement?.(preset.increment);
    if (preset.incrementMin) props.setIncrementMin?.(preset.incrementMin);
    if (preset.incrementMax) props.setIncrementMax?.(preset.incrementMax);
    if (preset.useRules !== undefined) props.setUseRules?.(preset.useRules);
  }

  function useAllPresetsInGroup(groupId: string) {
    // 1. 找到目标分组
    const group = props.presetGroups.find(g => g.id === groupId);
    if (!group) return;

    // 2. 获取分组中的所有预设（按分组内的顺序）
    const presetsInGroup = group.presetIds
      .map(id => props.presets.find(p => p.id === id))
      .filter((p): p is PresetConfig => p !== undefined);

    // 3. 如果分组为空，直接返回
    if (presetsInGroup.length === 0) return;

    // 4. 使用批量添加函数添加到攻击序列（不再使用 usePreset + onAddToSequence）
    props.addPresetsToSequence?.(presetsInGroup);
  }

  useEffect(() => {
    if (presetSelectAllCheckboxRef.current) {
      presetSelectAllCheckboxRef.current.indeterminate = getPresetSelectAllState() === "indeterminate";
    }
  }, [selectedPresetIds, managePresets, props.presetGroups, props.resourceTypeFilter, props.query]);


  function getPresetSelectAllState() {
    // 获取所有预设（未分组 + 分组内）
    const allPresets: PresetConfig[] = [...managePresets];
    props.presetGroups.forEach(group => {
      group.presetIds.forEach(presetId => {
        const preset = props.presets.find(p => p.id === presetId);
        if (preset && !allPresets.find(p => p.id === presetId)) {
          allPresets.push(preset);
        }
      });
    });
    
    // 应用过滤条件
    const filteredPresets = allPresets.filter(p => {
      // 攻击模式过滤
      if (props.resourceTypeFilter && String(p.attackMode) !== props.resourceTypeFilter) {
        return false;
      }
      // 搜索过滤
      return p.name.toLowerCase().includes(props.query.toLowerCase()) ||
            p.description?.toLowerCase().includes(props.query.toLowerCase());
    });
    
    // 根据过滤后的预设判断全选状态
    if (filteredPresets.length === 0) return "unchecked";
    if (filteredPresets.every(p => selectedPresetIds.includes(p.id))) return "checked";
    if (filteredPresets.some(p => selectedPresetIds.includes(p.id))) return "indeterminate";
    return "unchecked";
  }

  // 预设全选切换
  function togglePresetSelectAll(e: React.ChangeEvent<HTMLInputElement>) {
    if (e.target.checked) {
      // 获取所有预设（未分组 + 分组内）
      const allPresets: PresetConfig[] = [...managePresets];
      props.presetGroups.forEach(group => {
        group.presetIds.forEach(presetId => {
          const preset = props.presets.find(p => p.id === presetId);
          if (preset && !allPresets.find(p => p.id === presetId)) {
            allPresets.push(preset);
          }
        });
      });
      
      // 应用过滤条件并获取ID
      const filteredPresetIds = allPresets
        .filter(p => {
          // 攻击模式过滤
          if (props.resourceTypeFilter && String(p.attackMode) !== props.resourceTypeFilter) {
            return false;
          }
          // 搜索过滤
          return p.name.toLowerCase().includes(props.query.toLowerCase()) ||
                p.description?.toLowerCase().includes(props.query.toLowerCase());
        })
        .map(p => p.id);
      
      setSelectedPresetIds(filteredPresetIds);
    } else {
      setSelectedPresetIds([]);
    }
  }

  // 分组全选切换
  function togglePresetGroupSelect(groupId: string) {
    const group = props.presetGroups.find(g => g.id === groupId);
    if (!group) return;
    
    const isAllSelected = group.presetIds.every(id => selectedPresetIds.includes(id));
    
    if (isAllSelected) {
      // 取消选中该分组所有预设
      setSelectedPresetIds(prev => prev.filter(id => !group.presetIds.includes(id)));
    } else {
      // 选中该分组所有预设
      setSelectedPresetIds(prev => [...new Set([...prev, ...group.presetIds])]);
    }
  }

  // 获取分组选中状态
  function getPresetGroupCheckedState(groupId: string): "checked" | "unchecked" | "indeterminate" {
    const group = props.presetGroups.find(g => g.id === groupId);
    if (!group || group.presetIds.length === 0) return "unchecked";
    
    const allSelected = group.presetIds.every(id => selectedPresetIds.includes(id));
    const someSelected = group.presetIds.some(id => selectedPresetIds.includes(id));
    
    if (allSelected) return "checked";
    if (someSelected) return "indeterminate";
    return "unchecked";
  }


  // 检查路径是否在软件数据目录中
  function isInAppDataDirectory(path: string | null | undefined): boolean {
    if (!path) return false;
    
    // 检查是否在应用数据目录中（包含 imported-presets）
    const appDataPatterns = [
      "AppData\\Roaming\\com.hashcatgui.app",
      "/AppData/Roaming/com.hashcatgui.app",
      "custom-resource",     // 新增：自定义资源目录
      "imported-presets",    // 导入预设目录
      "imported-resource",   // 新增：导入资源目录
    ];
    
    return appDataPatterns.some(pattern => path.includes(pattern));
  }

  // 删除预设
  async function deletePreset(preset: PresetConfig) {
    // 1. 收集预设引用的所有文件路径
    const referencedPaths = [
      preset.dictionaryPath,
      preset.dictionaryPath2,
      ...(preset.dictionaryPaths || []),
      preset.maskPath,
      ...(preset.rulePaths || []),
    ]
    .filter((p): p is string => p !== undefined)
    .filter((p) => isInAppDataDirectory(p));
    
    // 2. 在删除前计算需要清理的文件（排除当前预设）
    const pathsToDelete: string[] = [];
    for (const path of referencedPaths) {
      if (!isPathReferencedExcludingPreset(path, preset.id)) {
        pathsToDelete.push(path);
      }
    }
    
    // 3. 删除预设并立即保存（关键修改）
    const updatedPresets = props.presets.filter((p) => p.id !== preset.id);
    props.setPresets(updatedPresets);
    
    // 立即保存到文件（不依赖 useEffect）
    try {
      const presetsJson = JSON.stringify(updatedPresets);
      await invoke("write_presets_file", { presetsJson, allowEmpty: updatedPresets.length === 0 });
    } catch (error) {
      console.error('Failed to save presets after delete:', error);
    }
    
    // 4. 取消选中
    if (selectedPresetId === preset.id) {
      setSelectedPresetId(null);
    }
    
    // 5. 立即清理文件
    for (const path of pathsToDelete) {
      try {
        await invoke("delete_custom_resource_file", { path });
      } catch {
        // 文件删除失败，忽略
      }
    }
  }

  // 检查文件路径是否被其他预设（排除指定预设）或自定义资源引用
  function isPathReferencedExcludingPreset(path: string, excludePresetId: string): boolean {
    // 1. 检查是否被自定义资源引用
    const referencedByResource = props.customResources.some(
      (r) => r.path === path
    );
    
    // 2. 检查是否被其他预设引用（排除当前正在删除的预设）
    const referencedByPreset = props.presets.some((p) => {
      if (p.id === excludePresetId) return false; // 排除当前预设
      const paths: (string | undefined)[] = [
        p.dictionaryPath,
        p.dictionaryPath2,
        ...(p.dictionaryPaths || []),
        p.maskPath,
        ...(p.rulePaths || []),
      ];
      return paths.some((refPath) => refPath === path);
    });
    
    return referencedByResource || referencedByPreset;
  }

  // 创建预设分组
  function createPresetGroup() {
    if (!newPresetGroupName.trim()) return;
    
    const newGroup: PresetGroup = {
      id: `preset-group-${Date.now()}`,
      name: newPresetGroupName.trim(),
      presetIds: [...selectedPresetIds],
      expanded: true
    };
    
    props.setPresetGroups(prev => [newGroup, ...prev]);
    setManagePresets(prev => prev.filter(p => !selectedPresetIds.includes(p.id)));
    setSelectedPresetIds([]);
    setNewPresetGroupName("");
    setShowCreatePresetGroupDialog(false);
  }

  // 移动预设到分组
  function movePresetsToGroup(targetGroupId: string) {
    if (targetGroupId) {
      // 移动到指定分组
      props.setPresetGroups(prev => {
        return prev.map(group => {
          if (group.id === targetGroupId) {
            const newPresetIds = [...new Set([...group.presetIds, ...selectedPresetIds])];
            return { ...group, presetIds: newPresetIds };
          }
          const newPresetIds = group.presetIds.filter(id => !selectedPresetIds.includes(id));
          return { ...group, presetIds: newPresetIds };
        });
      });
      
      setManagePresets(prev => prev.filter(p => !selectedPresetIds.includes(p.id)));
    } else {
      // 移动到无分组：只需从所有分组中移除
      props.setPresetGroups(prev => {
        return prev.map(group => {
          const newPresetIds = group.presetIds.filter(id => !selectedPresetIds.includes(id));
          return { ...group, presetIds: newPresetIds };
        });
      });
    }

    setSelectedPresetIds([]);
    setShowMovePresetToGroupDialog(false);
  }

  // 删除预设分组
  function deletePresetGroup(groupId: string) {
    const confirmText = isZh 
      ? `确定删除分组吗？分组内的预设将被移到未分组区域。` 
      : `Delete this group? Presets in the group will be moved to ungrouped area.`;
    
    if (confirm(confirmText)) {
      // 获取要删除的分组中的预设ID
      const group = props.presetGroups.find(g => g.id === groupId);
      if (group) {
        // 将预设移回未分组区域（只添加未被删除的预设）
        const groupPresets = props.presets.filter(p => 
          group.presetIds.includes(p.id) && !deletedPresetIds.includes(p.id)
        );
        setManagePresets(prev => [...prev, ...groupPresets]);
      }
      props.setPresetGroups(prev => prev.filter(g => g.id !== groupId));
    }
  }


  // 批量删除预设
  function batchDeletePresets() {
    // 1. 从管理列表中移除（视觉上移除）
    setManagePresets(prev => prev.filter(p => !selectedPresetIds.includes(p.id)));
    
    // 2. 记录到删除队列
    setDeletedPresetIds(prev => [...prev, ...selectedPresetIds]);
    
    // 3. 同时从分组中移除（管理模式内的临时操作）
    props.setPresetGroups(prev => prev.map(group => ({
      ...group,
      presetIds: group.presetIds.filter(id => !selectedPresetIds.includes(id))
    })));
    
    // 4. 清空选中状态
    setSelectedPresetIds([]);
  }

  // 分组移动到顶部
  function movePresetGroupToTop(groupId: string) {
    props.setPresetGroups(prev => {
      const group = prev.find(g => g.id === groupId);
      if (!group) return prev;
      return [group, ...prev.filter(g => g.id !== groupId)];
    });
  }

  // 分组移动到底部
  function movePresetGroupToBottom(groupId: string) {
    props.setPresetGroups(prev => {
      const group = prev.find(g => g.id === groupId);
      if (!group) return prev;
      return [...prev.filter(g => g.id !== groupId), group];
    });
  }

  // 分组上移
  function movePresetGroupUp(groupId: string) {
    props.setPresetGroups(prev => {
      const newGroups = [...prev];
      const index = newGroups.findIndex(g => g.id === groupId);
      if (index > 0) {
        [newGroups[index], newGroups[index - 1]] = [newGroups[index - 1], newGroups[index]];
      }
      return newGroups;
    });
  }

  // 分组下移
  function movePresetGroupDown(groupId: string) {
    props.setPresetGroups(prev => {
      const newGroups = [...prev];
      const index = newGroups.findIndex(g => g.id === groupId);
      if (index < newGroups.length - 1) {
        [newGroups[index], newGroups[index + 1]] = [newGroups[index + 1], newGroups[index]];
      }
      return newGroups;
    });
  }

  // 置顶（在同一分组或非分组区域内）
  function movePresetToTop(presetId: string) {
    props.setPresetGroups(prevGroups => {
      let foundInGroup = false;
      const newGroups = prevGroups.map(group => {
        if (group.presetIds.includes(presetId)) {
          foundInGroup = true;
          const newPresetIds = [presetId, ...group.presetIds.filter(id => id !== presetId)];
          return { ...group, presetIds: newPresetIds };
        }
        return group;
      });
      
      if (!foundInGroup) {
        setManagePresets(prev => {
          const preset = prev.find(p => p.id === presetId);
          if (!preset) return prev;
          return [preset, ...prev.filter(p => p.id !== presetId)];
        });
      }
      
      return newGroups;
    });
  }

  // 置底（在同一分组或非分组区域内）
  function movePresetToBottom(presetId: string) {
    props.setPresetGroups(prevGroups => {
      let foundInGroup = false;
      const newGroups = prevGroups.map(group => {
        if (group.presetIds.includes(presetId)) {
          foundInGroup = true;
          const newPresetIds = [...group.presetIds.filter(id => id !== presetId), presetId];
          return { ...group, presetIds: newPresetIds };
        }
        return group;
      });
      
      if (!foundInGroup) {
        setManagePresets(prev => {
          const preset = prev.find(p => p.id === presetId);
          if (!preset) return prev;
          return [...prev.filter(p => p.id !== presetId), preset];
        });
      }
      
      return newGroups;
    });
  }

  // 上移（在同一分组或非分组区域内）
  function movePresetUp(presetId: string) {
    props.setPresetGroups(prevGroups => {
      let foundInGroup = false;
      const newGroups = prevGroups.map(group => {
        if (group.presetIds.includes(presetId)) {
          foundInGroup = true;
          const index = group.presetIds.indexOf(presetId);
          if (index > 0) {
            const newPresetIds = [...group.presetIds];
            [newPresetIds[index], newPresetIds[index - 1]] = [newPresetIds[index - 1], newPresetIds[index]];
            return { ...group, presetIds: newPresetIds };
          }
        }
        return group;
      });
      
      if (!foundInGroup) {
        setManagePresets(prev => {
          const index = prev.findIndex(p => p.id === presetId);
          if (index <= 0) return prev;
          const newPresets = [...prev];
          [newPresets[index], newPresets[index - 1]] = [newPresets[index - 1], newPresets[index]];
          return newPresets;
        });
      }
      
      return newGroups;
    });
  }

  // 下移（在同一分组或非分组区域内）
  function movePresetDown(presetId: string) {
    props.setPresetGroups(prevGroups => {
      let foundInGroup = false;
      const newGroups = prevGroups.map(group => {
        if (group.presetIds.includes(presetId)) {
          foundInGroup = true;
          const index = group.presetIds.indexOf(presetId);
          if (index < group.presetIds.length - 1) {
            const newPresetIds = [...group.presetIds];
            [newPresetIds[index], newPresetIds[index + 1]] = [newPresetIds[index + 1], newPresetIds[index]];
            return { ...group, presetIds: newPresetIds };
          }
        }
        return group;
      });
      
      if (!foundInGroup) {
        setManagePresets(prev => {
          const index = prev.findIndex(p => p.id === presetId);
          if (index >= prev.length - 1) return prev;
          const newPresets = [...prev];
          [newPresets[index], newPresets[index + 1]] = [newPresets[index + 1], newPresets[index]];
          return newPresets;
        });
      }
      
      return newGroups;
    });
  }

  // 管理模式相关函数
  function startPresetManage() {
    // 获取未分组的预设（不在任何分组中的预设）
    const groupedPresetIds = props.presetGroups.flatMap(g => g.presetIds);
    const ungroupedPresets = props.presets.filter(p => !groupedPresetIds.includes(p.id));
    
    setManagePresets([...ungroupedPresets]);
    setOriginalPresetGroups([...props.presetGroups]);  // 保存原始分组状态用于取消操作
    setSelectedPresetIds([]);
    setDeletedPresetIds([]);
    setIsPresetManaging(true);
  }

  async function handleSavePresetManage() {
      // 1. 计算删除后的预设数量
      const remainingPresets = props.presets.filter(p => !deletedPresetIds.includes(p.id));
      const willBeEmpty = remainingPresets.length === 0;
      
      // 2. 执行删除操作
      props.setPresets(prev => prev.filter(p => !deletedPresetIds.includes(p.id)));
      
      // 3. 同步删除分组中的预设引用（删除的预设也要从分组中移除）
      props.setPresetGroups(prev => prev.map(group => ({
          ...group,
          presetIds: group.presetIds.filter(id => !deletedPresetIds.includes(id))
      })));
      
      // 4. 保存未分组预设的排序（关键：添加这部分逻辑）
      props.setPresets(prev => {
          // 获取已分组的预设ID
          const groupedIds = new Set(props.presetGroups.flatMap(g => g.presetIds));
          
          // 获取未分组的预设（按照 managePresets 的顺序）
          const ungroupedPresets = managePresets
              .filter(p => !deletedPresetIds.includes(p.id))
              .map(p => prev.find(existing => existing.id === p.id))
              .filter((p): p is PresetConfig => p !== undefined);
          
          // 获取已分组的预设（保持原有顺序）
          const groupedPresets = prev.filter(p => groupedIds.has(p.id) && !deletedPresetIds.includes(p.id));
          
          // 合并：未分组预设（按新顺序） + 已分组预设
          return [...ungroupedPresets, ...groupedPresets];
      });
      
      // 5. 如果所有预设都被删除，主动清空文件（管理模式允许清空）
      if (willBeEmpty) {
          try {
              await invoke("write_presets_file", { presetsJson: "[]", allowEmpty: true });
          } catch (error) {
              console.error('Failed to clear presets:', error);
          }
      }
      
      // 6. 清空所有状态
      setDeletedPresetIds([]);
      setIsPresetManaging(false);
      setSelectedPresetIds([]);
  }

  function handleCancelPresetManage() {
    // 1. 清空删除队列
    setDeletedPresetIds([]);
    
    // 2. 退出管理模式
    setIsPresetManaging(false);
    
    // 3. 清空选中状态
    setSelectedPresetIds([]);
    
    // 4. 恢复原始分组状态（撤销所有分组操作）
    props.setPresetGroups([...originalPresetGroups]);
  }

  // 初始化管理资源列表
  const initManageResources = () => {
    const combined: (CustomResource & { source: "custom" | "user" })[] = [
      ...props.customResources
        .map(r => ({ ...r, source: "custom" as const }))
        .sort((a, b) => (a.sortOrder || 0) - (b.sortOrder || 0)),  // 按排序顺序排列
      ...props.userDictionaries.map(dict => ({
        id: `userdict-${dict.path}`,
        type: "dictionary" as const,
        name: dict.name,
        description: "",
        path: dict.path,
        size: dict.size,
        createdAt: new Date().toISOString(),
        source: "user" as const
      }))
    ];
    setManageResources(combined);
  };

  // 切换选择单个资源
  const toggleSelect = (id: string) => {
    setSelectedIds(prev => 
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  // 全选/取消全选
  const toggleSelectAll = () => {
    const filteredResources = manageResources.filter(r => {
      if (props.resourceTypeFilter && r.type !== props.resourceTypeFilter) {
        return false;
      }
      return r.name.toLowerCase().includes(props.query.toLowerCase()) ||
            r.description?.toLowerCase().includes(props.query.toLowerCase());
    });
    const filterIds = filteredResources.map(r => r.id);
    setSelectedIds(prev => 
      prev.length === filterIds.length ? [] : filterIds
    );
  };

  // 获取全选状态
  const getSelectAllState = () => {
    const filteredResources = manageResources.filter(r => {
      if (props.resourceTypeFilter && r.type !== props.resourceTypeFilter) {
        return false;
      }
      return r.name.toLowerCase().includes(props.query.toLowerCase()) ||
            r.description?.toLowerCase().includes(props.query.toLowerCase());
    });
    const filterIds = filteredResources.map(r => r.id);
    const selectedCount = selectedIds.filter(id => filterIds.includes(id)).length;
    if (selectedCount === 0) return "unchecked";
    if (selectedCount === filterIds.length) return "checked";
    return "indeterminate";
  };

  // 移动到顶部（在同一分组或非分组区域内）
  const moveToTop = (id: string) => {
    setGroups(prevGroups => {
      // 检查资源是否在某个分组内
      let foundInGroup = false;
      const newGroups = prevGroups.map(group => {
        if (group.resourceIds.includes(id)) {
          foundInGroup = true;
          // 在分组内移动到顶部
          const newResourceIds = [id, ...group.resourceIds.filter(rId => rId !== id)];
          return { ...group, resourceIds: newResourceIds };
        }
        return group;
      });
      
      // 如果不在分组内，移动非分组资源到顶部
      if (!foundInGroup) {
        setManageResources(prev => {
          const newItems = [...prev];
          const index = newItems.findIndex(item => item.id === id);
          if (index > 0) {
            const [removed] = newItems.splice(index, 1);
            newItems.unshift(removed);
          }
          return newItems;
        });
      }
      
      return newGroups;
    });
  };

  // 置底（在同一分组或非分组区域内）
  const moveToBottom = (id: string) => {
    setGroups(prevGroups => {
      let foundInGroup = false;
      const newGroups = prevGroups.map(group => {
        if (group.resourceIds.includes(id)) {
          foundInGroup = true;
          const newResourceIds = [...group.resourceIds.filter(rId => rId !== id), id];
          return { ...group, resourceIds: newResourceIds };
        }
        return group;
      });
      
      // 如果不在分组内，移动非分组资源到底部
      if (!foundInGroup) {
        setManageResources(prev => {
          const newItems = [...prev];
          const index = newItems.findIndex(item => item.id === id);
          if (index >= 0 && index < newItems.length - 1) {
            const [removed] = newItems.splice(index, 1);
            newItems.push(removed);
          }
          return newItems;
        });
      }
      
      return newGroups;
    });
  };

  // 上移（在同一分组或非分组区域内）
  const moveUp = (id: string) => {
    setGroups(prevGroups => {
      let foundInGroup = false;
      const newGroups = prevGroups.map(group => {
        if (group.resourceIds.includes(id)) {
          foundInGroup = true;
          const index = group.resourceIds.indexOf(id);
          if (index > 0) {
            const newResourceIds = [...group.resourceIds];
            [newResourceIds[index], newResourceIds[index - 1]] = [newResourceIds[index - 1], newResourceIds[index]];
            return { ...group, resourceIds: newResourceIds };
          }
        }
        return group;
      });
      
      if (!foundInGroup) {
        setManageResources(prev => {
          const newItems = [...prev];
          const index = newItems.findIndex(item => item.id === id);
          if (index > 0) {
            [newItems[index], newItems[index - 1]] = [newItems[index - 1], newItems[index]];
          }
          return newItems;
        });
      }
      
      return newGroups;
    });
  };

  // 下移（在同一分组或非分组区域内）
  const moveDown = (id: string) => {
    setGroups(prevGroups => {
      let foundInGroup = false;
      const newGroups = prevGroups.map(group => {
        if (group.resourceIds.includes(id)) {
          foundInGroup = true;
          const index = group.resourceIds.indexOf(id);
          if (index < group.resourceIds.length - 1) {
            const newResourceIds = [...group.resourceIds];
            [newResourceIds[index], newResourceIds[index + 1]] = [newResourceIds[index + 1], newResourceIds[index]];
            return { ...group, resourceIds: newResourceIds };
          }
        }
        return group;
      });
      
      if (!foundInGroup) {
        setManageResources(prev => {
          const newItems = [...prev];
          const index = newItems.findIndex(item => item.id === id);
          if (index < newItems.length - 1) {
            [newItems[index], newItems[index + 1]] = [newItems[index + 1], newItems[index]];
          }
          return newItems;
        });
      }
      
      return newGroups;
    });
  };

  // 分组移动到顶部
  const moveGroupToTop = (groupId: string) => {
    setGroups(prev => {
      const group = prev.find(g => g.id === groupId);
      if (!group) return prev;
      return [group, ...prev.filter(g => g.id !== groupId)];
    });
  };

  // 分组移动到底部
  const moveGroupToBottom = (groupId: string) => {
    setGroups(prev => {
      const group = prev.find(g => g.id === groupId);
      if (!group) return prev;
      return [...prev.filter(g => g.id !== groupId), group];
    });
  };

  // 分组上移
  const moveGroupUp = (groupId: string) => {
    setGroups(prev => {
      const newGroups = [...prev];
      const index = newGroups.findIndex(g => g.id === groupId);
      if (index > 0) {
        [newGroups[index], newGroups[index - 1]] = [newGroups[index - 1], newGroups[index]];
      }
      return newGroups;
    });
  };

  // 分组下移
  const moveGroupDown = (groupId: string) => {
    setGroups(prev => {
      const newGroups = [...prev];
      const index = newGroups.findIndex(g => g.id === groupId);
      if (index < newGroups.length - 1) {
        [newGroups[index], newGroups[index + 1]] = [newGroups[index + 1], newGroups[index]];
      }
      return newGroups;
    });
  };

  // 批量删除
  const batchRemove = () => {
    // 1. 记录要删除的ID到删除队列
    setDeletedIds(prev => [...prev, ...selectedIds]);
    
    // 2. 从本地管理列表移除（只是视觉上移除）
    setManageResources(prev => prev.filter(r => !selectedIds.includes(r.id)));
    
    // 3. 从分组中移除
    setGroups(prev => prev.map(group => ({
      ...group,
      resourceIds: group.resourceIds.filter(id => !selectedIds.includes(id))
    })));
    
    // 4. 清空选中状态
    setSelectedIds([]);
  };

  // 完成管理
  const handleSaveManage = async () => {
    // 1. 批量删除用户字典
    deletedIds.filter(id => id.startsWith("userdict-")).forEach(id => {
      props.removeDictionary(id.replace("userdict-", ""));
    });
    
    // 2. 批量删除自定义资源（一次性过滤）
    const customIdsToDelete = deletedIds.filter(id => !id.startsWith("userdict-"));
    if (customIdsToDelete.length > 0) {
      const remaining = props.customResources.filter(r => !customIdsToDelete.includes(r.id));
      
      // 批量删除文件（检查引用）
      for (const r of props.customResources.filter(r => customIdsToDelete.includes(r.id))) {
        if (r.path) {
          const isInAppData = (r.path.includes("custom-resource") || r.path.includes("imported-resource")) &&
                             (r.path.includes("AppData") || r.path.includes("Roaming"));
          if (isInAppData) {
            const referencedByOther = remaining.some(res => res.path === r.path);
            const referencedByPreset = props.presets?.some(preset => {
              const paths = [preset.dictionaryPath, preset.dictionaryPath2, ...(preset.dictionaryPaths || []), preset.maskPath];
              return paths.includes(r.path);
            }) ?? false;
            if (!referencedByOther && !referencedByPreset) {
              try { await invoke("delete_custom_resource_file", { path: r.path }); } catch {}
            }
          }
        }
      }
      
      // 一次性更新状态
      props.setCustomResources?.(remaining);
      try { await invoke("write_custom_resources_file", { resourcesJson: JSON.stringify(remaining) }); } 
      catch (e) { console.error(e); }
    }
    
    // 3. 更新自定义资源排序（用户字典不参与排序）
    const customIdsToDeleteSet = new Set(deletedIds.filter(id => !id.startsWith("userdict-")));
    const customResourcesOnly = manageResources.filter(r => r.source === "custom" && !customIdsToDeleteSet.has(r.id));
    
    customResourcesOnly.forEach((resource, index) => {
      const existing = props.customResources.find(r => r.id === resource.id);
      if (existing) {
        const updatedResource: CustomResource = {
          ...existing,
          sortOrder: index
        };
        props.saveCustomResource(updatedResource);
      }
    });
    
    invoke("write_resource_groups_file", { groupsJson: JSON.stringify(groups) })
      .catch(console.error);

    // 4. 清空所有状态
    setSelectedIds([]);
    setDeletedIds([]);
    setIsManaging(false);
  };

  // 取消管理
  const handleCancelManage = () => {
    setSelectedIds([]);
    setDeletedIds([]);  // ← 清空删除队列
    setIsManaging(false);
    initManageResources();  // ← 重新初始化，恢复原始列表
    setGroups([...originalGroups]);
  };

  // 进入管理模式时初始化
  const startManage = () => {
    initManageResources();
    setOriginalGroups([...groups]);
    setEditingGroupId(null);
    setEditingGroupName("");
    setIsManaging(true);
  };

  async function openResourceDirectory(path: string) {
    try {
      await invoke("open_file_directory", { filePath: path });
    } catch (err) {
      console.error("Failed to open directory:", err);
    }
  }

  async function previewResource(resource: Pick<ResourceInfo, "name" | "path">, allowFull = false) {
    try {
      setPreviewName(resource.name);
      setPreview(await invoke<FilePreviewResponse>("preview_text_file", { path: resource.path, allowFull }));
    } catch (err) {
      setPreviewName(resource.name);
      setPreview({ path: resource.path, content: String(err), truncated: false, lineCount: 1, fileSize: 0, previewLimit: 0 });
    }
  }

  const [showExportDialog, setShowExportDialog] = useState(false);
  const [showImportDialog, setShowImportDialog] = useState(false);
  const [showImportPreview, setShowImportPreview] = useState(false);
  const [isConflictDialogOpen, setIsConflictDialogOpen] = useState(false);
  const [conflictData, setConflictData] = useState<ConflictInfo[]>([]);
  const [_conflictResolve, setConflictResolve] = useState<((value: ImportMode | null) => void) | null>(null);
  const [exportType, setExportType] = useState<'preset' | 'custom'>('preset');
  const [selectedExportGroups, setSelectedExportGroups] = useState<string[]>([]);
  const [exportName, setExportName] = useState('');
  const [importPreviewData, setImportPreviewData] = useState<ImportPreviewData | null>(null);
  const [importSourcePath, setImportSourcePath] = useState('');
  const [isZipImport, setIsZipImport] = useState(false);
  const [tempExtractPath, setTempExtractPath] = useState('');


  // 导出文件统计（改为 useState + useEffect 异步方式）
  const [exportFileCount, setExportFileCount] = useState(0);
  const [exportTotalSize, setExportTotalSize] = useState(0);

  // 异步计算导出文件数量和大小（去重）
  useEffect(() => {
    if (selectedExportGroups.length === 0) {
      setExportFileCount(0);
      setExportTotalSize(0);
      return;
    }

  async function calculateExportStats() {
    // 先收集所有路径到数组
    const allPaths: string[] = [];

    if (exportType === 'preset') {
      // 预设导出：收集所有文件路径（不检查重复）
      selectedExportGroups.forEach(groupId => {
        const group = props.presetGroups.find(g => g.id === groupId);
        if (group) {
          group.presetIds.forEach(presetId => {
            const preset = props.presets.find(p => p.id === presetId);
            if (preset) {
              // 收集所有路径到数组
              if (preset.dictionaryPath) allPaths.push(preset.dictionaryPath);
              if (preset.dictionaryPath2) allPaths.push(preset.dictionaryPath2);
              if (preset.dictionaryPaths) allPaths.push(...preset.dictionaryPaths);
              if (preset.maskPath) allPaths.push(preset.maskPath);
              if (preset.rulePaths) allPaths.push(...preset.rulePaths);
            }
          });
        }
      });
    } else {
      // 资源导出：收集所有文件路径
      selectedExportGroups.forEach(groupId => {
        const group = groups.find(g => g.id === groupId);
        if (group) {
          group.resourceIds.forEach(resourceId => {
            const resource = props.customResources.find(r => r.id === resourceId);
            if (resource && resource.path) {
              allPaths.push(resource.path);
            }
          });
        }
      });
    }

    // 使用 Set 统一去重，转换为 Map
    const uniquePaths = [...new Set(allPaths)];
    const fileSizes = new Map<string, number>();
    
    // 初始化 Map
    uniquePaths.forEach(path => fileSizes.set(path, 0));

    // 预设导出需要异步获取文件大小
    if (exportType === 'preset') {
      for (const path of uniquePaths) {
        try {
          const response = await invoke<FilePreviewResponse>("preview_text_file", {
            path: path,
            allowFull: false
          });
          fileSizes.set(path, response.fileSize);
        } catch {
          fileSizes.set(path, 0);
        }
      }
    } else {
      // 资源导出：直接使用资源的 size 属性
      uniquePaths.forEach(path => {
        const resource = props.customResources.find(r => r.path === path);
        if (resource && resource.size) {
          fileSizes.set(path, resource.size);
        }
      });
    }

    // 计算总数
    const totalSize = Array.from(fileSizes.values()).reduce((sum, size) => sum + size, 0);

    setExportFileCount(fileSizes.size);
    setExportTotalSize(totalSize);
  }

  void calculateExportStats();
}, [exportType, selectedExportGroups, props.presetGroups, props.presets, groups, props.customResources]);


  async function showConflictDialog(conflicts: ConflictInfo[]): Promise<ImportMode | null> {
      // 先关闭导入预览窗口
      setShowImportPreview(false);
      
      return new Promise((resolve) => {
          setConflictData(conflicts);
          // 使用回调函数确保 resolve 被正确保存
          setConflictResolve(() => resolve);
          setIsConflictDialogOpen(true);
      });
  }

  const handleConflictAction = (action: ImportMode | null) => {
      // 使用回调方式获取当前的 resolve 函数
      setConflictResolve((currentResolve: ((value: ImportMode | null) => void) | null) => {
          if (currentResolve) {
              currentResolve(action);
          }
          return null;
      });
      setIsConflictDialogOpen(false);
      setConflictData([]);
  };

  // 检查导出资源的有效性，返回无效文件列表
  async function checkExportResources(): Promise<string[]> {
    const allPaths: string[] = [];

    if (exportType === 'preset') {
      // 预设导出：收集所有文件路径
      selectedExportGroups.forEach(groupId => {
        const group = props.presetGroups.find(g => g.id === groupId);
        if (group) {
          group.presetIds.forEach(presetId => {
            const preset = props.presets.find(p => p.id === presetId);
            if (preset) {
              if (preset.dictionaryPath) allPaths.push(preset.dictionaryPath);
              if (preset.dictionaryPath2) allPaths.push(preset.dictionaryPath2);
              if (preset.dictionaryPaths) allPaths.push(...preset.dictionaryPaths);
              if (preset.maskPath) allPaths.push(preset.maskPath);
              if (preset.rulePaths) allPaths.push(...preset.rulePaths);
            }
          });
        }
      });
    } else {
      // 资源导出：收集所有文件路径
      selectedExportGroups.forEach(groupId => {
        const group = groups.find(g => g.id === groupId);
        if (group) {
          group.resourceIds.forEach(resourceId => {
            const resource = props.customResources.find(r => r.id === resourceId);
            if (resource && resource.path) {
              allPaths.push(resource.path);
            }
          });
        }
      });
    }

    // 去重
    const uniquePaths = [...new Set(allPaths)];
    
    // 检查所有文件是否存在
    const results = await Promise.all(
      uniquePaths.map(async path => ({
        path,
        exists: await invoke<boolean>("check_file_exists", { path })
      }))
    );

    // 返回不存在的文件列表
    return results.filter(r => !r.exists).map(r => r.path);
  }

  const handleExport = async () => {
    if (selectedExportGroups.length === 0) return;
    
    try {
      const invalidResources = await checkExportResources();
      if (invalidResources.length > 0) {
        props.setError?.(
          isZh 
            ? `以下资源文件不存在或已失效：\n${invalidResources.join('，')}` 
            : `The following resource files are missing or invalid:\n${invalidResources.join(', ')}`
        );
        const checkedPresets = await Promise.all(
          props.presets.map(async (preset: PresetConfig) => ({
            ...preset,
            isValid: await props.checkPresetFiles?.(preset),
          }))
        );
        props.setPresets(checkedPresets);
        await props.onRefreshResources?.();
        return; // 中止导出
      }

      // 获取目标目录
      const targetDir = await open({
        directory: true,
        title: isZh ? "选择导出目录" : "Select Export Directory"
      });
      
      if (!targetDir) return;

      // 自动生成导出名称（如果用户没有输入）
      let finalExportName = exportName.trim();
      if (!finalExportName) {
        // 获取选中分组的名称
        const allGroups = exportType === 'preset' ? props.presetGroups : groups;
        const selectedGroupNames = selectedExportGroups
          .map(id => allGroups.find(g => g.id === id)?.name)
          .filter(Boolean);
        
        if (selectedGroupNames.length === 1) {
          // 只有一个分组，使用该分组名
          finalExportName = selectedGroupNames[0]!;
        } else if (selectedGroupNames.length > 1) {
          // 多个分组，使用 "分组名1 + 分组名2 ..." 格式
          finalExportName = selectedGroupNames.join(' + ');
        } else {
          // 没有选中分组（理论上不会发生）
          props.showToast?.(isZh ? "无法生成导出名称" : "Cannot generate export name");
          return;
        }
      }
      
      // 获取当前类型的所有数据
      const groupsData = exportType === 'preset' 
        ? JSON.stringify(props.presetGroups) 
        : JSON.stringify(groups);
      const itemsData = exportType === 'preset' 
        ? JSON.stringify(props.presets) 
        : JSON.stringify(props.customResources);
      
      // 调用后端导出命令
      if (exportType === 'preset') {
        await invoke('export_presets', {
          presetGroupsJson: groupsData,
          presetsJson: itemsData,
          selectedGroupIds: selectedExportGroups,
          targetDir: targetDir,
          exportName: finalExportName  
        });
      } else {
        await invoke('export_resources', {
          resourceGroupsJson: groupsData,
          resourcesJson: itemsData,
          selectedGroupIds: selectedExportGroups,
          targetDir: targetDir,
          exportName: finalExportName  
        });
      }
      
      setShowExportDialog(false);
      setSelectedExportGroups([]);
      setExportName('');
      props.showToast?.(isZh ? "导出成功！" : "Export successful!");
    } catch (error) {
      console.error('导出失败:', error);
      props.setError?.(isZh ? `导出失败: ${error}` : `Export failed: ${error}`);
    }
  };

  const handleImportSelectFolder = async () => {
  try {
    const folderPath = await open({
      directory: true,
      title: isZh ? "选择导出文件夹" : "Select Export Folder"
    });
    
    if (!folderPath) return;
    
    const previewData: ImportPreviewData = await invoke('read_export_metadata', {
      folderPath: folderPath
    });
    
    setImportPreviewData(previewData);
    setImportSourcePath(folderPath);
    setIsZipImport(false);  // 标记为文件夹导入
    setTempExtractPath('');
    setShowImportDialog(false);
    setShowImportPreview(true);
  } catch (error) {
    console.error('读取导出文件夹失败:', error);
    props.showToast?.(isZh ? `读取失败: ${error}` : `Failed to read: ${error}`);
    }
  };

  const handleImportSelectZip = async () => {
    try {
      const zipPath = await open({
        directory: false,
        title: isZh ? "选择压缩文件" : "Select Zip File",
        filters: [
          { name: 'Zip Files', extensions: ['zip'] }
        ]
      });
      
      if (!zipPath) return;
      
      // 解压到临时目录
      const extractPath = await invoke('extract_zip_to_temp', {
        zipPath: zipPath
      }) as string;
      
      // 读取导出元数据进行预览
      const previewData: ImportPreviewData = await invoke('read_export_metadata', {
        folderPath: extractPath
      }) as ImportPreviewData;
      
      setImportPreviewData(previewData);
      setImportSourcePath(extractPath);
      setIsZipImport(true);  // 标记为压缩文件导入
      setTempExtractPath(extractPath);
      setShowImportDialog(false);
      setShowImportPreview(true);
    } catch (error) {
      console.error('读取压缩文件失败:', error);
      props.showToast?.(isZh ? `读取失败: ${error}` : `Failed to read: ${error}`);
    }
  };

  const handleImportConfirm = async () => {
    if (!importSourcePath || !importPreviewData) return;
    
    try {
      let result: ImportResult;
      let finalSourcePath = importSourcePath;
      
      // 如果是从压缩文件导入，先移动文件夹到目标位置
      if (isZipImport && tempExtractPath) {
        finalSourcePath = await invoke('move_export_to_external', {
          sourcePath: tempExtractPath
        });
        setImportSourcePath(finalSourcePath);
      }
      
      // 执行导入（使用更新后的路径）
      if (importPreviewData.type === 'preset') {
        // 预设导入逻辑...
        const previewResult: ImportPreviewResult = await invoke('preview_import_presets', {
          folderPath: finalSourcePath
        });
        
        if (previewResult.conflicts.length > 0) {
          const selectedMode = await showConflictDialog(previewResult.conflicts);
          if (!selectedMode) {
            // 用户取消，清理已移动的文件夹
            if (isZipImport) {
              await invoke('remove_temp_dir', { tempPath: finalSourcePath });
            }
            return;
          }
          result = await invoke('import_presets', {
            folderPath: finalSourcePath,
            importMode: selectedMode
          });
        } else {
          result = await invoke('import_presets', {
            folderPath: finalSourcePath,
            importMode: 'merge'
          });
        }
        
        if (result.success) {
          props.showToast?.(isZh ? "导入成功！" : "Import successful!");
          await props.onRefreshPresets?.();
          
        } else {
          // 导入失败，清理已移动的文件夹
          if (isZipImport) {
            await invoke('remove_temp_dir', { tempPath: finalSourcePath });
          }
          props.showToast?.(isZh ? `导入失败: ${result.message}` : `Import failed: ${result.message}`);
        }
      } else {
        // 资源导入逻辑...
        const previewResult: ImportPreviewResult = await invoke('preview_import_resources', {
          folderPath: finalSourcePath
        });
        
        if (previewResult.conflicts.length > 0) {
          const selectedMode = await showConflictDialog(previewResult.conflicts);
          if (!selectedMode) {
            if (isZipImport) {
              await invoke('remove_temp_dir', { tempPath: finalSourcePath });
            }
            return;
          }
          result = await invoke('import_resources', {
            folderPath: finalSourcePath,
            importMode: selectedMode
          });
        } else {
          result = await invoke('import_resources', {
            folderPath: finalSourcePath,
            importMode: 'merge'
          });
        }
        
        if (result.success) {
          props.showToast?.(isZh ? "导入成功！" : "Import successful!");
          await props.onRefreshPresets?.();
        } else {
          if (isZipImport) {
            await invoke('remove_temp_dir', { tempPath: finalSourcePath });
          }
          props.showToast?.(isZh ? `导入失败: ${result.message}` : `Import failed: ${result.message}`);
        }
      }
      
      setShowImportPreview(false);
      setImportPreviewData(null);
      setImportSourcePath('');
      setIsZipImport(false);
      setTempExtractPath('');
    } catch (error) {
      // 异常失败，清理已移动的文件夹
      if (isZipImport && importSourcePath) {
        await invoke('remove_temp_dir', { tempPath: importSourcePath });
      }
      console.error('导入失败:', error);
      props.showToast?.(isZh ? `导入失败: ${error}` : `Import failed: ${error}`);
    }
  };

  return (
    <div className="tab-content resources-tab">
      {managerOpen && (
        <CustomResourceManager
          resources={props.customResources}
          userDictionaries={props.userDictionaries}
          text={props.text}
          onClose={() => setManagerOpen(false)}
          onSave={props.saveCustomResource}
          onDelete={props.deleteCustomResource}
          onUse={props.useCustomResource}
          onRemoveDictionary={props.removeDictionary}
        />
      )}
      {preview && (
        <ResourcePreviewDialog
          name={previewName}
          preview={preview}
          text={props.text}
          onClose={() => setPreview(null)}
        />
      )}
      {addResourceOpen && (
        <AddCustomResourceDialog
          text={props.text}
          onClose={() => {
            setAddResourceOpen(false);
            setEditingResource(null);  // 清空编辑状态
          }}
          onSave={(resource) => props.saveCustomResource(resource, selectedResourceGroupId ?? undefined)}
          editing={editingResource}  // 传入要编辑的资源
        />
      )}
      <div className="panel-heading">
        <div><p className="eyebrow">Resources</p><h2>{props.text.resourcesTitle}</h2></div>
      </div>
      <div className="resource-search-bar">
        <select className="resource-type-filter" value={props.resourceTypeFilter} onChange={(e) => props.setResourceTypeFilter(e.target.value)}>
          {activeTab === "preset" ? (
            // 预设选项卡：按攻击模式过滤
            <>
              <option value="">{props.text.allTypes} ({props.presets.length})</option>
              <option value="0">{isZh ? "字典攻击" : "Dictionary Attack"} ({props.presets.filter(p => p.attackMode === 0).length})</option>
              <option value="3">{isZh ? "掩码攻击" : "Mask Attack"} ({props.presets.filter(p => p.attackMode === 3).length})</option>
              <option value="1">{isZh ? "字典组合攻击" : "Combined Dictionary"} ({props.presets.filter(p => p.attackMode === 1).length})</option>
              <option value="6">{isZh ? "字典+掩码攻击" : "Dict + Mask"} ({props.presets.filter(p => p.attackMode === 6).length})</option>
              <option value="7">{isZh ? "掩码+字典攻击" : "Mask + Dict"} ({props.presets.filter(p => p.attackMode === 7).length})</option>
              <option value="9">{isZh ? "候选模板攻击" : "Template Attack"} ({props.presets.filter(p => p.attackMode === 9).length})</option>
            </>
          ) : activeTab === "custom" ? (
            // 自定义选项卡：按资源类型过滤
            <>
              <option value="">{props.text.allTypes} ({props.customResources.length})</option>
              <option value="dictionary">{props.text.resourceDictionary} ({props.customResources.filter(r => r.type === "dictionary").length})</option>
              <option value="mask">{props.text.resourceMask} ({props.customResources.filter(r => r.type === "mask").length})</option>
              <option value="rule">{props.text.resourceRule} ({props.customResources.filter(r => r.type === "rule").length})</option>
              <option value="template">{props.text.resourceTemplate} ({props.customResources.filter(r => r.type === "template").length})</option>
              <option value="charset">{props.text.resourceCharset} ({props.customResources.filter(r => r.type === "charset").length})</option>
            </>
          ) : (
            // 内置选项卡：按资源类型过滤
            <>
              <option value="">{props.text.allTypes} ({props.resources.length})</option>
              <option value="dictionary">{props.text.resourceDictionary} ({props.resources.filter(r => r.kind === "dictionary").length})</option>
              <option value="mask">{props.text.resourceMask} ({props.resources.filter(r => r.kind === "mask").length})</option>
              <option value="rule">{props.text.resourceRule} ({props.resources.filter(r => r.kind === "rule").length})</option>
              <option value="template">{props.text.resourceTemplate} ({props.resources.filter(r => r.kind === "charset").length})</option>
              <option value="charset">{props.text.resourceCharset} ({props.resources.filter(r => r.kind === "charset").length})</option>
            </>
          )}
        </select>
        <input value={props.query} onChange={(event) => props.setQuery(event.currentTarget.value)} placeholder={props.text.resourceSearch} />
        <label className="simple-mode-toggle">
          <input type="checkbox" checked={props.simpleMode} onChange={(e) => props.setSimpleMode(e.target.checked)} />
          <span className="slider-wrapper">
            <span className="slider"></span>
          </span>
          <span className="toggle-label">{isZh ? "简约模式" : "Simple Mode"}</span>
        </label>
      </div>
      
      {/* 选项卡头部 */}
      <div className="resource-tabs-header">
        <button 
          type="button" 
          className={`tab-button ${activeTab === "preset" ? "active" : ""}`}
          onClick={() => {
            setActiveTab("preset");
            props.setResourceTypeFilter("");  // 重置过滤值
          }}
        >
          {props.text.presets} ({props.presets.length}) 
        </button>
        <button 
          type="button" 
          className={`tab-button ${activeTab === "custom" ? "active" : ""}`}
          onClick={() => {
            setActiveTab("custom");
            props.setResourceTypeFilter("");  // 重置过滤值
          }}
        >
          {props.text.customResources} ({props.customResources.length}) 
        </button>
        <button 
          type="button" 
          className={`tab-button ${activeTab === "builtin" ? "active" : ""}`}
          onClick={() => {
            setActiveTab("builtin");
            props.setResourceTypeFilter("");  // 重置过滤值
          }}
        >
          {props.text.builtinResources} ({props.resources.length}) 
        </button>
        
        <div className="resource-header-actions">
          <button 
            className="small-button import-btn" 
            onClick={() => setShowImportDialog(true)}
          >
            <ArrowDownToLine size={14} />
            <span>{isZh ? "导入" : "Import"}</span>
          </button>
          <button 
            className="small-button export-btn" 
            onClick={() => setShowExportDialog(true)}
          >
            <ArrowUpToLine size={14} />
            <span>{isZh ? "导出" : "Export"}</span>
          </button>
        </div>
      </div>
      
      {/* 选项卡内容区域 */}
      <div className="resource-tabs-content">
        {/* 预设选项卡内容 */}
        {activeTab === "preset" && (
          <div className="resource-tab-panel">
            {/* 预设列表区域 - 可滚动 */}
            <div className="resource-list compact resource-custom-list">
              {(() => {
                // 根据模式决定数据源
                const presetsToRender = (isPresetManaging ? managePresets : props.presets).filter(p => {
                  // 攻击模式过滤（预设选项卡）
                  if (activeTab === "preset" && props.resourceTypeFilter) {
                    if (String(p.attackMode) !== props.resourceTypeFilter) {
                      return false;
                    }
                  }
                  // 搜索过滤
                  return p.name.toLowerCase().includes(props.query.toLowerCase()) ||
                        p.description?.toLowerCase().includes(props.query.toLowerCase());
                });

                if (!isPresetManaging) {
                  // 获取所有已分组的预设ID
                  const groupedPresetIds = new Set(props.presetGroups.flatMap(g => g.presetIds));
                  
                  // 过滤掉已分组的预设
                  const ungroupedPresets = presetsToRender.filter(p => !groupedPresetIds.has(p.id));
                  
                  // 如果没有分组且没有未分组预设，显示空状态
                  if (props.presetGroups.length === 0 && ungroupedPresets.length === 0) {
                    return <div className="empty-state">{props.text.noPresets}</div>;
                  }

                  return (
                    <>
                      {/* 渲染分组 - 使用简化的分组头部（不带管理按钮） */}
                      {props.presetGroups.map(group => {
                        // 获取分组中的预设 - 按照 group.presetIds 的顺序返回
                        const groupPresets = group.presetIds
                          .map(id => presetsToRender.find(p => p.id === id))
                          .filter((p): p is PresetConfig => p !== undefined);

                        const isGroupSelected = !isPresetManaging && selectedPresetGroupId === group.id;
                        return (
                          <div key={group.id} className={`resource-group${group.expanded ? '' : ' collapsed'}${isGroupSelected ? ' selected' : ''}`}>
                            <div className="group-header" onClick={() => {
                              props.setPresetGroups(prev => prev.map(g => g.id === group.id ? { ...g, expanded: !g.expanded } : g));
                              if (!isPresetManaging) {
                                setSelectedPresetGroupId(isGroupSelected ? null : group.id);
                                setSelectedPresetId(null);
                              }
                            }}>
                              <button type="button" className="group-toggle" onClick={(e) => {
                                e.stopPropagation();
                                props.setPresetGroups(prev => prev.map(g => g.id === group.id ? { ...g, expanded: !g.expanded } : g));
                              }}>
                                {group.expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                              </button>
                              {editingPresetGroupId === group.id ? (
                                <input
                                  type="text"
                                  className="group-name-input"
                                  value={editingPresetGroupName}
                                  onChange={(e) => setEditingPresetGroupName(e.target.value)}
                                  onKeyDown={(e) => {
                                    if (e.key === 'Enter') {
                                      if (editingPresetGroupName.trim()) {
                                        props.setPresetGroups(prev => prev.map(g => 
                                          g.id === group.id ? { ...g, name: editingPresetGroupName.trim() } : g
                                        ));
                                      }
                                      setEditingPresetGroupId(null);
                                    } else if (e.key === 'Escape') {
                                      setEditingPresetGroupId(null);
                                    }
                                  }}
                                  onBlur={() => {
                                    if (editingPresetGroupName.trim()) {
                                      props.setPresetGroups(prev => prev.map(g => 
                                        g.id === group.id ? { ...g, name: editingPresetGroupName.trim() } : g
                                      ));
                                    }
                                    setEditingPresetGroupId(null);
                                  }}
                                  autoFocus
                                />
                              ) : (
                                <span 
                                  className="group-name"
                                  onDoubleClick={() => {
                                    setEditingPresetGroupId(group.id);
                                    setEditingPresetGroupName(group.name);
                                  }}
                                >{group.name}</span>
                              )}
                              <span className="group-count">({groupPresets.length})</span>
                              <div className="group-actions">
                                <button 
                                  type="button" 
                                  className="group-useall"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    useAllPresetsInGroup(group.id);
                                  }}
                                  disabled={groupPresets.length === 0}
                                >
                                  <span>{isZh ? "使用全部" : "Use All"}</span>
                                </button>
                              </div>
                            </div>
                            <div className="group-content">
                              {groupPresets.map(preset => renderPresetItem(preset, true))}
                            </div>
                          </div>
                        );
                      })}
                      {/* 渲染未分组预设 */}
                      {ungroupedPresets.map(preset => renderPresetItem(preset, false))}
                    </>
                  );
                }

                // ========== 管理模式下的分组渲染 ==========
                
                // 渲染单个预设项
                function renderPresetItem(preset: PresetConfig, isInGroup: boolean = false) {
                  const isSelected = isPresetManaging ? selectedPresetIds.includes(preset.id) : preset.id === selectedPresetId;
                  
                  const handleClick = () => {
                    if (isPresetManaging) {
                      // 管理模式：多选逻辑
                      setSelectedPresetIds(prev => 
                        prev.includes(preset.id) 
                          ? prev.filter(id => id !== preset.id)
                          : [...prev, preset.id]
                      );
                    } else {
                      // 非管理模式：单选逻辑（点击已选中的取消选中）
                      setSelectedPresetId(isSelected ? null : preset.id);
                      setSelectedPresetGroupId(null);
                    }
                  };
                  const isValid = preset.isValid !== false;

                  return (
                    <div 
                      className={`resource-row ${isSelected ? "active" : ""} ${isPresetManaging ? "selectable" : ""} ${isInGroup ? "in-group" : ""} ${!isValid ? "invalid" : ""}`} 
                      key={preset.id}
                      onClick={handleClick}
                    >
                      {/* 管理模式下显示复选框 */}
                      {isPresetManaging && (
                        <div className="resource-checkbox">
                          <input 
                            type="checkbox" 
                            checked={isSelected} 
                            onClick={(e) => e.stopPropagation()} 
                            onChange={(e) => { e.stopPropagation(); handleClick(); }} 
                          />
                        </div>
                      )}
                      
                      <div className="resource-content">
                        <div className="resource-header">
                          {/* 攻击类型标签 */}
                          <span className={`resource-type-badge resource-type-${attackModeToType(preset.attackMode)}`}>
                            {attackModeLabel(preset.attackMode, props.text)}{isZh ? "攻击" : "Attack"}
                          </span>
                          {editingPresetId === preset.id ? (
                            <input
                              type="text"
                              className="preset-name-input"
                              value={editingPresetName}
                              onChange={(e) => setEditingPresetName(e.target.value)}
                              onKeyDown={(e) => {
                                if (e.key === 'Enter') {
                                  // 回车保存
                                  if (editingPresetName.trim()) {
                                    props.setPresets(prev => prev.map(p => 
                                      p.id === preset.id ? { ...p, name: editingPresetName.trim() } : p
                                    ));
                                  }
                                  setEditingPresetId(null);
                                } else if (e.key === 'Escape') {
                                  // ESC 取消
                                  setEditingPresetId(null);
                                }
                              }}
                              onBlur={() => {
                                // 失去焦点保存
                                if (editingPresetName.trim()) {
                                  props.setPresets(prev => prev.map(p => 
                                    p.id === preset.id ? { ...p, name: editingPresetName.trim() } : p
                                  ));
                                }
                                setEditingPresetId(null);
                              }}
                              autoFocus
                            />
                          ) : (
                            <strong 
                              className="preset-name"
                              onDoubleClick={() => {
                                // 双击进入编辑模式
                                setEditingPresetId(preset.id);
                                setEditingPresetName(preset.name);
                              }}
                            >
                              {!isValid && <span className="resource-invalid">({props.text.resourceInvalid})</span>}{preset.name}
                            </strong>
                          )}
                        </div>
                        
                        {/* 第二行：显示字典路径或掩码 */}
                        {!props.simpleMode && (
                          <span>
                            {preset.detailDisplay || generatePresetDetail(preset, props.text, isZh)}
                          </span>
                        )}
                        {/* 第三行：描述 */}
                        {!props.simpleMode && (
                          <em>{preset.description || props.text.noDescription}</em>
                        )}
                      </div>
                      
                      {/* 操作按钮 */}
                      <div className="resource-actions">
                        {isPresetManaging ? (
                          // 管理模式显示排序按钮
                          <>
                            <button type="button" onClick={(e) => { e.stopPropagation(); movePresetToTop(preset.id); }} title={isZh ? "置顶" : "Move to top"}>
                              <ArrowUpToLine size={14} />
                            </button>
                            <button type="button" onClick={(e) => { e.stopPropagation(); movePresetToBottom(preset.id); }} title={isZh ? "置底" : "Move to bottom"}>
                              <ArrowDownToLine size={14} />
                            </button>
                            <button type="button" onClick={(e) => { e.stopPropagation(); movePresetUp(preset.id); }} title={isZh ? "上移" : "Move up"}>
                              <ChevronUp size={14} />
                            </button>
                            <button type="button" onClick={(e) => { e.stopPropagation(); movePresetDown(preset.id); }} title={isZh ? "下移" : "Move down"}>
                              <ChevronDown size={14} />
                            </button>
                          </>
                        ) : (
                          // 普通模式显示使用和删除按钮
                          <>
                            <button type="button" onClick={(e) => { e.stopPropagation(); usePreset(preset); }}>{props.text.use}</button>
                            <button type="button" onClick={(e) => { e.stopPropagation(); deletePreset(preset); }}><Trash2 size={14} /></button>
                          </>
                        )}
                      </div>
                    </div>
                  );
                }

                // 渲染分组
                const renderPresetGroups = () => {
                  return props.presetGroups.map(group => {
                    // 获取分组中的预设 - 按照 group.presetIds 的顺序返回，确保排序操作生效
                    const groupPresets = group.presetIds
                      .map(id => props.presets.find(p => p.id === id))
                      .filter((p): p is PresetConfig => {
                        if (!p || deletedPresetIds.includes(p.id)) {
                          return false;
                        }
                        // 应用攻击模式过滤
                        if (activeTab === "preset" && props.resourceTypeFilter && String(p.attackMode) !== props.resourceTypeFilter) {
                          return false;
                        }
                        // 应用搜索过滤
                        if (!p.name.toLowerCase().includes(props.query.toLowerCase()) && 
                            !p.description?.toLowerCase().includes(props.query.toLowerCase())) {
                          return false;
                        }
                        return true;
                      });
                    
                    const isGroupSelected = !isPresetManaging && selectedPresetGroupId === group.id;
                    return (
                      <div key={group.id} className={`resource-group${group.expanded ? '' : ' collapsed'}`}>
                        <div className="group-header" onClick={() => props.setPresetGroups(prev => prev.map(g => g.id === group.id ? { ...g, expanded: !g.expanded } : g))}>
                          {isPresetManaging && (
                            <div className="group-checkbox">
                              <input 
                                type="checkbox" 
                                checked={getPresetGroupCheckedState(group.id) !== "unchecked"}
                                ref={(el) => {
                                  if (el) {
                                    el.indeterminate = getPresetGroupCheckedState(group.id) === "indeterminate";
                                  }
                                }}
                                onClick={(e) => e.stopPropagation()}
                                onChange={(e) => { 
                                  e.stopPropagation(); 
                                  togglePresetGroupSelect(group.id); 
                                }} 
                              />
                            </div>
                          )}
                          <button type="button" className="group-toggle" onClick={(e) => {
                            e.stopPropagation();
                            props.setPresetGroups(prev => prev.map(g => g.id === group.id ? { ...g, expanded: !g.expanded } : g));
                            if (!isPresetManaging) {
                              setSelectedPresetGroupId(isGroupSelected ? null : group.id);
                              setSelectedPresetId(null);
                            }
                          }}>
                            {group.expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                          </button>
                          {editingPresetGroupId === group.id ? (
                            <input
                              type="text"
                              className="group-name-input"
                              value={editingPresetGroupName}
                              onChange={(e) => setEditingPresetGroupName(e.target.value)}
                              onKeyDown={(e) => {
                                if (e.key === 'Enter') {
                                  if (editingPresetGroupName.trim()) {
                                    props.setPresetGroups(prev => prev.map(g => 
                                      g.id === group.id ? { ...g, name: editingPresetGroupName.trim() } : g
                                    ));
                                  }
                                  setEditingPresetGroupId(null);
                                } else if (e.key === 'Escape') {
                                  setEditingPresetGroupId(null);
                                }
                              }}
                              onBlur={() => {
                                if (editingPresetGroupName.trim()) {
                                  props.setPresetGroups(prev => prev.map(g => 
                                    g.id === group.id ? { ...g, name: editingPresetGroupName.trim() } : g
                                  ));
                                }
                                setEditingPresetGroupId(null);
                              }}
                              autoFocus
                            />
                          ) : (
                            <span 
                              className="group-name" 
                              onDoubleClick={() => {
                                setEditingPresetGroupId(group.id);
                                setEditingPresetGroupName(group.name);
                              }}
                            >
                              {group.name}
                            </span>
                          )}
                          <span className="group-count">({groupPresets.length})</span>
                          {isPresetManaging && (
                            <>
                              <div className="group-actions">
                                <button 
                                  type="button" 
                                  className="group-move-btn" 
                                  onClick={(e) => { e.stopPropagation(); movePresetGroupToTop(group.id); }}
                                  title={isZh ? "分组置顶" : "Move group to top"}
                                >
                                  <ArrowUpToLine size={14} />
                                </button>
                                <button 
                                  type="button" 
                                  className="group-move-btn" 
                                  onClick={(e) => { e.stopPropagation(); movePresetGroupToBottom(group.id); }}
                                  title={isZh ? "分组置底" : "Move group to bottom"}
                                >
                                  <ArrowDownToLine size={14} />
                                </button>
                                <button 
                                  type="button" 
                                  className="group-move-btn" 
                                  onClick={(e) => { e.stopPropagation(); movePresetGroupUp(group.id); }}
                                  title={isZh ? "分组上移" : "Move group up"}
                                >
                                  <ChevronUp size={14} />
                                </button>
                                <button 
                                  type="button" 
                                  className="group-move-btn" 
                                  onClick={(e) => { e.stopPropagation(); movePresetGroupDown(group.id); }}
                                  title={isZh ? "分组下移" : "Move group down"}
                                >
                                  <ChevronDown size={14} />
                                </button>
                                
                                {/* 解除分组按钮 */}
                                <button 
                                  type="button" 
                                  className="group-ungroup" 
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    deletePresetGroup(group.id);
                                  }}
                                >
                                  <span>{isZh ? "解除分组" : "Ungroup"}</span>
                                </button>
                                {/* 删除分组按钮（新增） */}
                                <button 
                                  type="button" 
                                  className="group-ungroup" 
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    // 删除分组内所有预设
                                    group.presetIds.forEach(presetId => {
                                      const preset = props.presets.find(p => p.id === presetId);
                                      if (preset) {
                                        // 将预设ID添加到删除队列
                                        setDeletedPresetIds(prev => [...prev, presetId]);
                                      }
                                    });
                                    
                                    // 从分组列表中移除该分组
                                    props.setPresetGroups(prev => prev.filter(g => g.id !== group.id));
                                    
                                    // 从管理列表中移除分组内的预设
                                    setManagePresets(prev => prev.filter(p => !group.presetIds.includes(p.id)));
                                  }}
                                >
                                  <span>{isZh ? "删除分组" : "Delete Group"}</span>
                                </button>
                              </div>
                            </>
                          )}
                        </div>
                        <div className="group-content">
                          {groupPresets.map(p => renderPresetItem(p, true))}
                        </div>
                      </div>
                    );
                  });
                };

                // 获取所有已分组的预设ID
                const groupedPresetIds = new Set(props.presetGroups.flatMap(g => g.presetIds));

                // 过滤掉已分组的预设
                const ungroupedPresets = presetsToRender.filter(p => 
                  !groupedPresetIds.has(p.id) && !deletedPresetIds.includes(p.id)
                );

                // 如果没有分组且没有未分组预设，显示空状态
                if (props.presetGroups.length === 0 && ungroupedPresets.length === 0) {
                  return <div className="empty-state">{props.text.noPresets}</div>;
                }

                return (
                  <>
                    {renderPresetGroups()}
                    {ungroupedPresets.map((preset, _index) => renderPresetItem(preset, false))}
                  </>
                );
              })()}
            </div>
            
            {/* 底部固定操作按钮栏 */}
            {isPresetManaging ? (
              // 管理模式按钮栏
              <div className="manage-actions-bar">
                <div className="manage-actions-left">
                  <label className="select-all-label">
                    <input 
                      ref={presetSelectAllCheckboxRef}
                      type="checkbox" 
                      checked={getPresetSelectAllState() === "checked"}
                      onChange={togglePresetSelectAll}
                    />
                    <span>{isZh ? "全选" : "Select All"}</span>
                  </label>
                </div>
                <div className="manage-actions-center">
                  <button type="button" onClick={() => setShowCreatePresetGroupDialog(true)}>
                    <FolderPlus size={14} />{isZh ? "新建分组" : "Create Group"}
                  </button>
                  <button type="button" onClick={() => setShowMovePresetToGroupDialog(true)} disabled={selectedPresetIds.length === 0 || props.presetGroups.length === 0}>
                    <FolderOutput size={14} />{isZh ? "移动分组" : "Move to Group"}
                  </button>
                  
                  <button type="button" onClick={batchDeletePresets} disabled={selectedPresetIds.length === 0} className="danger-button">
                    <Trash2 size={14} />{isZh ? "删除" : "Delete"}
                  </button>
                </div>
                <div className="manage-actions-right">
                  <button type="button" onClick={handleSavePresetManage} className="primary-button">
                    {isZh ? "保存" : "Save"}
                  </button>
                  <button type="button" onClick={handleCancelPresetManage} className="ghost-button">
                    {isZh ? "取消" : "Cancel"}
                  </button>
                </div>
              </div>
            ) : (
              // 普通模式按钮栏
              <div className="resource-actions-bar">
                <button 
                  type="button" 
                  className="action-button add-button" 
                  onClick={() => setShowAddPresetDialog(true)}
                >
                  <Plus size={14} />{selectedPresetGroupId ? props.text.addToGroup : props.text.add}
                </button>
                <button 
                  type="button" 
                  className="action-button edit-button" 
                  disabled={!selectedPresetId}
                  onClick={() => {
                    const selected = props.presets.find(p => p.id === selectedPresetId);
                    if (selected) {
                      setEditingPreset(selected);
                      setShowAddPresetDialog(true);
                    }
                  }}
                >
                  <Edit3 size={14} />{props.text.edit}
                </button>
                <button type="button" className="action-button manage-button" onClick={startPresetManage}>
                  <Settings size={14} />{(isZh ? "管理" : "Manage")}
                </button>
              </div>
            )}

            {showAddPresetDialog && (
              <AddPresetDialog
                text={props.text}
                onClose={() => {
                  setShowAddPresetDialog(false);
                  setEditingPreset(null);
                }}
                onSave={(preset) => {
                  if (editingPreset) {
                    // 编辑模式：先保存预设，然后触发重新计算密码量
                    props.setPresets(prev => prev.map(p => p.id === preset.id ? preset : p));
                  } else {
                    // 新建模式：添加预设后触发计算
                    props.setPresets(prev => [...prev, preset]);
                    
                    // 如果选中了分组，将新预设添加到该分组
                    if (selectedPresetGroupId) {
                      props.setPresetGroups(prev => prev.map(group => {
                        if (group.id === selectedPresetGroupId) {
                          return { ...group, presetIds: [...group.presetIds, preset.id] };
                        }
                        return group;
                      }));
                    }
                  }
                  // 重新计算候选空间和详情信息
                  estimatePresetCandidates(preset);
                }}
                resources={props.filteredResources || []}
                userDictionaries={props.userDictionaries}
                customResources={props.customResources}
                editing={editingPreset}
                ruleEditorTarget={ruleEditorTarget}
                openRuleEditor={(target) => setRuleEditorTarget(target)}
                onRuleEditorApply={() => {}}
              />
            )}
            {/* 新建预设分组对话框 */}
            {showCreatePresetGroupDialog && (
              <div className="modal-backdrop" role="presentation">
                <section className="simple-dialog" role="dialog" aria-modal="true">
                  <div className="panel-heading">
                    <div>
                      <p className="eyebrow">Group</p>
                      <h2>{isZh ? "新建预设分组" : "Create Preset Group"}</h2>
                    </div>
                    <button 
                      className="icon-button" 
                      type="button" 
                      onClick={() => setShowCreatePresetGroupDialog(false)}
                    >
                      <X size={15} />
                    </button>
                  </div>
                  <div className="dialog-body">
                    <div className="form-group">
                      <label>{isZh ? "分组名称" : "Group Name"}</label>
                      <input 
                        type="text" 
                        value={newPresetGroupName} 
                        onChange={(e) => setNewPresetGroupName(e.target.value)} 
                        placeholder={isZh ? "请输入分组名称" : "Enter group name"}
                        autoFocus
                      />
                    </div>
                    {selectedPresetIds.length > 0 && (
                      <div className="form-group">
                        <p className="hint">
                          {isZh 
                            ? `将选中的 ${selectedPresetIds.length} 个预设添加到新分组` 
                            : `Add ${selectedPresetIds.length} selected presets to new group`
                          }
                        </p>
                      </div>
                    )}
                  </div>
                  <div className="dialog-actions">
                    <button 
                      className="ghost-button" 
                      type="button" 
                      onClick={() => setShowCreatePresetGroupDialog(false)}
                    >
                      {props.text.cancel}
                    </button>
                    <button 
                      className="primary-button" 
                      type="button" 
                      onClick={createPresetGroup}
                      disabled={!newPresetGroupName.trim()}
                    >
                      {props.text.save}
                    </button>
                  </div>
                </section>
              </div>
            )}
            {/* 移动预设到分组对话框 */}
            {showMovePresetToGroupDialog && props.presetGroups.length > 0 && (
              <div className="modal-backdrop" role="presentation">
                <section className="simple-dialog" role="dialog" aria-modal="true">
                  <div className="panel-heading">
                    <div>
                      <p className="eyebrow">Group</p>
                      <h2>{isZh ? "移动到分组" : "Move to Group"}</h2>
                    </div>
                    <button 
                      className="icon-button" 
                      type="button" 
                      onClick={() => setShowMovePresetToGroupDialog(false)}
                    >
                      <X size={15} />
                    </button>
                  </div>
                  <div className="dialog-body">
                    <div className="form-group">
                      <label>{isZh ? "选择分组" : "Select Group"}</label>
                      <select id="preset-group-select">
                        <option key="ungrouped" value="">{isZh ? "无分组" : "Ungrouped"}</option>
                        {props.presetGroups.map(group => (
                          <option key={group.id} value={group.id}>
                            {group.name}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>
                  <div className="dialog-actions">
                    <button 
                      className="ghost-button" 
                      type="button" 
                      onClick={() => setShowMovePresetToGroupDialog(false)}
                    >
                      {props.text.cancel}
                    </button>
                    <button 
                      className="primary-button" 
                      type="button" 
                      onClick={() => {
                        const selectElement = document.getElementById("preset-group-select") as HTMLSelectElement;
                        movePresetsToGroup(selectElement.value);
                      }}
                    >
                      {props.text.save}
                    </button>
                  </div>
                </section>
              </div>
            )}
          </div>
        )}

        {/* 自定义资源 */}
        {activeTab === "custom" && (
          <div className="resource-tab-panel">
            {/* 资源列表区域 - 可滚动 */}
            <div className="resource-list compact resource-custom-list">
              {(() => {
                type ResourceWithSource = CustomResource & { source: "custom" | "user" };

                const combinedResources: ResourceWithSource[] = [
                  ...props.customResources
                    .map(r => ({ ...r, source: "custom" as const }))
                    .sort((a, b) => (a.sortOrder || 0) - (b.sortOrder || 0)),  // 按排序顺序排列
                  ...props.userDictionaries.map(dict => ({
                    id: `userdict-${dict.path}`,
                    type: "dictionary" as const,
                    name: dict.name,
                    description: "",
                    path: dict.path,
                    size: dict.size,
                    createdAt: new Date().toISOString(),
                    source: "user" as const
                  }))
                ];
                
                const filteredCustom = combinedResources.filter(r => {
                  if (props.resourceTypeFilter && r.type !== props.resourceTypeFilter) {
                    return false;
                  }
                  return r.name.toLowerCase().includes(props.query.toLowerCase()) ||
                        r.description?.toLowerCase().includes(props.query.toLowerCase());
                });

                // 修改1：判断使用哪个列表
                const resourcesToRender = isManaging ? 
                  manageResources.filter(r => {
                    if (props.resourceTypeFilter && r.type !== props.resourceTypeFilter) {
                      return false;
                    }
                    return r.name.toLowerCase().includes(props.query.toLowerCase()) ||
                          r.description?.toLowerCase().includes(props.query.toLowerCase());
                  }) : filteredCustom;

                // ========== 新增：分组相关函数 ==========
                // 获取分组内的资源
                const getResourceInGroup = (groupId: string) => {
                  const group = groups.find(g => g.id === groupId);
                  if (!group) return [];
                  // 按照 group.resourceIds 的顺序返回资源，确保排序操作生效
                  // 使用 filteredCustom 而不是 combinedResources，确保过滤逻辑生效
                  return group.resourceIds
                    .map(id => filteredCustom.find(r => r.id === id))
                    .filter((r): r is ResourceWithSource => r !== undefined);
                };

                // 获取分组勾选状态
                const getGroupCheckedState = (groupId: string): "checked" | "unchecked" | "indeterminate" => {
                  const groupResources = getResourceInGroup(groupId);
                  const groupResourceIds = groupResources.map(r => r.id);
                  
                  // 获取分组内已选中的资源数量
                  const selectedCount = groupResourceIds.filter(id => selectedIds.includes(id)).length;
                  
                  if (selectedCount === 0) return "unchecked";
                  if (selectedCount === groupResourceIds.length) return "checked";
                  return "indeterminate";
                };

                // 切换分组勾选状态
                const toggleGroupSelect = (groupId: string) => {
                  const groupResources = getResourceInGroup(groupId);
                  const groupResourceIds = groupResources.map(r => r.id);
                  const isAllSelected = groupResourceIds.every(id => selectedIds.includes(id));
                  
                  if (isAllSelected) {
                    // 取消选中分组内所有资源
                    setSelectedIds(prev => prev.filter(id => !groupResourceIds.includes(id)));
                  } else {
                    // 选中分组内所有资源
                    setSelectedIds(prev => [...new Set([...prev, ...groupResourceIds])]);
                  }
                };


                // 渲染资源项（提取为函数）
                const renderResourceItem = (resource: ResourceWithSource, isInGroupOrIndex?: boolean | number) => {
                  const isInGroup = typeof isInGroupOrIndex === 'boolean' ? isInGroupOrIndex : false;
                  const isUserDict = resource.source === "user";
                  const isValid = resource.isValid !== false;

                  // 修改2：修改选中状态判断
                  const isSelected = isManaging ? selectedIds.includes(resource.id) : resource.id === selectedResourceId;
                  
                  // 修改3：修改点击事件处理
                  const handleClick = () => {
                    if (isManaging) {
                      toggleSelect(resource.id);
                    } else {
                      setSelectedResourceId(isSelected ? null : resource.id);
                      setSelectedResourceGroupId(null);
                    }
                  };
                  
                  return (
                    <div 
                      className={`resource-row ${isSelected ? "active" : ""} ${isManaging ? "selectable" : ""} ${isInGroup ? "in-group" : ""} ${!isValid ? "invalid" : ""}`} 
                      key={resource.id}
                      onClick={handleClick}
                    >
                      {/* 修改4：添加复选框（管理模式） */}
                      {isManaging && (
                        <div className="resource-checkbox">
                          <input 
                            type="checkbox" 
                            checked={isSelected} 
                            onClick={(e) => e.stopPropagation()} 
                            onChange={(e) => { e.stopPropagation(); toggleSelect(resource.id); }} 
                          />
                        </div>
                      )}
                      
                      <div className="resource-content">
                        <div className="resource-header">
                          <span className={`resource-type-badge resource-type-${isUserDict ? "dictionary" : resource.type}`}>
                            {isUserDict ? (props.text.resourceDictionary || "Dict") : resourceTypeBadgeText(resource.type, props.text)}
                          </span>
                          {editingResourceId === resource.id ? (
                            // 编辑模式：显示输入框
                            <input
                              type="text"
                              className="preset-name-input"
                              value={editingResourceName}
                              onChange={(e) => setEditingResourceName(e.target.value)}
                              onKeyDown={(e) => {
                                if (e.key === 'Enter') {
                                  // 回车保存
                                  if (editingResourceName.trim()) {
                                    if (isUserDict) {
                                      // 用户字典：使用新方法更新
                                      props.updateUserDictionaryName(resource.path!, editingResourceName.trim());
                                    } else {
                                      // 自定义资源：使用 saveCustomResource 更新
                                      const updatedResource: CustomResource = {
                                        ...resource,
                                        name: editingResourceName.trim(),
                                      };
                                      props.saveCustomResource(updatedResource);
                                    }
                                  }
                                  setEditingResourceId(null);
                                } else if (e.key === 'Escape') {
                                  // ESC 取消
                                  setEditingResourceId(null);
                                }
                              }}
                              onBlur={() => {
                                // 失去焦点保存
                                if (editingResourceName.trim()) {
                                  if (isUserDict) {
                                    // 用户字典：使用新方法更新
                                    props.updateUserDictionaryName(resource.path!, editingResourceName.trim());
                                  } else {
                                    // 自定义资源：使用 saveCustomResource 更新
                                    const updatedResource: CustomResource = {
                                      ...resource,
                                      name: editingResourceName.trim()
                                    };
                                    props.saveCustomResource(updatedResource);
                                  }
                                }
                                setEditingResourceId(null);
                              }}
                              autoFocus
                            />
                          ) : (
                            // 普通模式：显示名称，绑定双击事件
                            <strong 
                              onDoubleClick={() => {
                                setEditingResourceId(resource.id);
                                setEditingResourceName(resource.name);
                              }}
                            >{!isValid && <span className="resource-invalid">({props.text.resourceInvalid})</span>}{resource.name}</strong>
                          )}
                        </div>
                        {!props.simpleMode && (
                          <span>
                            {isUserDict ? props.text.userDictionaries : customResourceTypeLabel(resource, props.text)} · 
                            {isUserDict ? `${formatSize(resource.size!)} · ${shortPath(resource.path!)}` : customResourceValue(resource)}
                          </span>
                        )}
                        {!props.simpleMode && (
                          <em>{isUserDict ? props.text.resourceDictionaryHelp : resource.description || (resource.type === "mask" ? props.text.resourceMaskFileHelp : props.text.templateHint)}</em>
                        )}  
                        </div>
                      
                      {/* 修改5：修改操作按钮 */}
                      <div className="resource-actions">
                        {isManaging ? (
                          // 管理模式下显示排序按钮
                          <>
                            <button type="button" onClick={(e) => { e.stopPropagation(); moveToTop(resource.id); }} title={isZh ? "置顶" : "Move to top"}>
                              <ArrowUpToLine size={14} />
                            </button>
                            <button type="button" onClick={(e) => { e.stopPropagation(); moveToBottom(resource.id); }} title={isZh ? "置底" : "Move to bottom"}>
                              <ArrowDownToLine size={14} />
                            </button>
                            <button type="button" onClick={(e) => { e.stopPropagation(); moveUp(resource.id); }} title={isZh ? "上移" : "Move up"}>
                              <ChevronUp size={14} />
                            </button>
                            <button type="button" onClick={(e) => { e.stopPropagation(); moveDown(resource.id); }} title={isZh ? "下移" : "Move down"}>
                              <ChevronDown size={14} />
                            </button>
                          </>
                        ) : isUserDict ? (
                          // 普通模式 - 用户字典
                          <>
                            <button type="button" onClick={(e) => { e.stopPropagation(); void previewResource({ name: resource.name, path: resource.path! }, true); }}>{props.text.preview}</button>
                            <button type="button" onClick={(e) => { e.stopPropagation(); props.useResource({ kind: "dictionary", name: resource.name, path: resource.path!, size: resource.size! }); }}>{props.text.use}</button>
                            <button type="button" onClick={(e) => { e.stopPropagation(); props.removeDictionary(resource.path!); }}><Trash2 size={14} /></button>
                          </>
                        ) : (
                          // 普通模式 - 自定义资源
                          <>
                            {resource.path && (
                              <button type="button" onClick={(e) => {
                                e.stopPropagation();
                                void previewResource({ name: resource.name, path: resource.path! });
                              }}>{props.text.preview}</button>
                            )}
                            <button type="button" onClick={(e) => { e.stopPropagation(); props.useCustomResource(resource); }}>{props.text.use}</button>
                            <button type="button" onClick={(e) => { e.stopPropagation(); props.deleteCustomResource(resource); }}><Trash2 size={14} /></button>
                          </>
                        )}
                      </div>
                    </div>
                  );
                };

                // 渲染分组
                const renderGroups = () => {
                  if (groups.length === 0) return null;
                  
                  return groups.map(group => {
                    const groupResources = getResourceInGroup(group.id);
                    const hasVisibleResources = groupResources.some(r => {
                      if (props.resourceTypeFilter && r.type !== props.resourceTypeFilter) return false;
                      return r.name.toLowerCase().includes(props.query.toLowerCase()) ||
                            r.description?.toLowerCase().includes(props.query.toLowerCase());
                    });
                    
                    if (!group.expanded && !hasVisibleResources && groupResources.length > 0) return null;
                    const isGroupSelected = !isManaging && selectedResourceGroupId === group.id;
                    return (
                      <div key={group.id} className={`resource-group${group.expanded ? '' : ' collapsed'}${isGroupSelected ? ' selected' : ''}`}>
                        <div className="group-header" onClick={() => {
                          setGroups(prev => prev.map(g => g.id === group.id ? { ...g, expanded: !g.expanded } : g));
                          // 非管理模式下：选中分组，清除资源选中状态（互斥）
                          if (!isManaging) {
                            setSelectedResourceGroupId(isGroupSelected ? null : group.id);
                            setSelectedResourceId(null);
                          }
                        }}>
                          {isManaging && (
                            <div className="group-checkbox">
                              <input 
                                type="checkbox" 
                                checked={getGroupCheckedState(group.id) !== "unchecked"}
                                ref={(el) => {
                                  if (el) {
                                    el.indeterminate = getGroupCheckedState(group.id) === "indeterminate";
                                  }
                                }}
                                onClick={(e) => e.stopPropagation()}
                                onChange={(e) => { 
                                  e.stopPropagation(); 
                                  toggleGroupSelect(group.id); 
                                }} 
                              />
                            </div>
                          )}
                          <button type="button" className="group-toggle" onClick={(e) => {
                            e.stopPropagation();
                            // 添加展开收起逻辑
                            setGroups(prev => prev.map(g => g.id === group.id ? { ...g, expanded: !g.expanded } : g));
                          }}>
                            {group.expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                          </button>
                          {editingGroupId === group.id ? (
                            <input
                              type="text"
                              className="group-name-input"
                              value={editingGroupName}
                              onChange={(e) => setEditingGroupName(e.target.value)}
                              onKeyDown={(e) => {
                                if (e.key === 'Enter') {
                                  // 回车保存
                                  if (editingGroupName.trim()) {
                                    setGroups(prev => prev.map(g => 
                                      g.id === group.id ? { ...g, name: editingGroupName.trim() } : g
                                    ));
                                  }
                                  setEditingGroupId(null);
                                } else if (e.key === 'Escape') {
                                  // ESC取消
                                  setEditingGroupId(null);
                                }
                              }}
                              onBlur={() => {
                                // 失去焦点保存
                                if (editingGroupName.trim()) {
                                  setGroups(prev => prev.map(g => 
                                    g.id === group.id ? { ...g, name: editingGroupName.trim() } : g
                                  ));
                                }
                                setEditingGroupId(null);
                              }}
                              autoFocus
                            />
                          ) : (
                            <span 
                              className="group-name" 
                              onDoubleClick={() => {
                                setEditingGroupId(group.id);
                                setEditingGroupName(group.name);
                              }}
                            >
                              {group.name}
                            </span>
                          )}
                          <span className="group-count">({groupResources.length})</span>
                          {isManaging && (
                            <>
                              <div className="group-actions">
                                <button 
                                  type="button" 
                                  className="group-move-btn" 
                                  onClick={(e) => { e.stopPropagation(); moveGroupToTop(group.id); }}
                                  title={isZh ? "分组置顶" : "Move group to top"}
                                >
                                  <ArrowUpToLine size={14} />
                                </button>
                                <button 
                                  type="button" 
                                  className="group-move-btn" 
                                  onClick={(e) => { e.stopPropagation(); moveGroupToBottom(group.id); }}
                                  title={isZh ? "分组置底" : "Move group to bottom"}
                                >
                                  <ArrowDownToLine size={14} />
                                </button>
                                <button 
                                  type="button" 
                                  className="group-move-btn" 
                                  onClick={(e) => { e.stopPropagation(); moveGroupUp(group.id); }}
                                  title={isZh ? "分组上移" : "Move group up"}
                                >
                                  <ChevronUp size={14} />
                                </button>
                                <button 
                                  type="button" 
                                  className="group-move-btn" 
                                  onClick={(e) => { e.stopPropagation(); moveGroupDown(group.id); }}
                                  title={isZh ? "分组下移" : "Move group down"}
                                >
                                  <ChevronDown size={14} />
                                </button>
                                
                                {/* 解除分组按钮 */}
                                <button 
                                  type="button" 
                                  className="group-ungroup" 
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    const groupResources = getResourceInGroup(group.id);
                                    setManageResources(prev => [...prev, ...groupResources]);
                                    setGroups(prev => prev.filter(g => g.id !== group.id));
                                  }}
                                >
                                  <span>{isZh ? "解除分组" : "Ungroup"}</span>
                                </button>
                                {/* 删除分组按钮（新增） */}
                                <button 
                                  type="button" 
                                  className="group-ungroup" 
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    // 获取分组内的所有资源
                                    const groupResources = getResourceInGroup(group.id);
                                    
                                    // 将分组内所有资源ID添加到删除队列
                                    setDeletedIds(prev => [...prev, ...groupResources.map(r => r.id)]);
                                    
                                    // 从分组列表中移除该分组
                                    setGroups(prev => prev.filter(g => g.id !== group.id));
                                    
                                    // 从管理列表中移除分组内的资源
                                    setManageResources(prev => prev.filter(r => !group.resourceIds.includes(r.id)));
                                  }}
                                >
                                  <span>{isZh ? "删除分组" : "Delete Group"}</span>
                                </button>
                              </div>
                            </>
                          )}
                        </div>
                        <div className="group-content">
                          {groupResources.map(r => renderResourceItem(r, true))}
                        </div>
                      </div>
                    );
                  });
                };
                // ========== 分组相关函数结束 ==========
                // 获取所有已分组的资源ID
                const groupedResourceIds = new Set(groups.flatMap(g => g.resourceIds));

                // 过滤掉已分组的资源
                const ungroupedResources = resourcesToRender.filter(r => !groupedResourceIds.has(r.id));

                return (
                  <>
                    {renderGroups()}
                    {ungroupedResources.length ? ungroupedResources.map(renderResourceItem) : (groups.length === 0 ? <div className="empty-state">{props.text.noCustomResources}</div> : null)}
                  </>
                );
              })()}
            </div>
            
            {/* 底部固定操作按钮栏 - 独立于滚动区域 */}
            {isManaging ? (
              // 管理模式下的按钮栏
              <div className="manage-actions-bar">
                <div className="manage-actions-left">
                  <label className="select-all-label">
                    <input 
                      type="checkbox" 
                      checked={getSelectAllState() === "checked"}
                      ref={selectAllCheckboxRef}
                      onChange={toggleSelectAll}
                    />
                    <span>{isZh ? "全选" : "Select All"}</span>
                  </label>
                </div>
                <div className="manage-actions-center">
                  <button type="button" onClick={() => setShowCreateGroupDialog(true)}>
                    <FolderPlus size={14} />{isZh ? "新建分组" : "Create Group"}
                  </button>
                  <button type="button" onClick={() => setShowMoveToGroupDialog(true)} disabled={selectedIds.length === 0 || groups.length === 0}>
                    <FolderOutput size={14} />{isZh ? "移动分组" : "Move to Group"}
                  </button>
                  
                  <button type="button" onClick={batchRemove} disabled={selectedIds.length === 0} className="danger-button">
                    <Trash2 size={14} />{isZh ? "删除" : "Delete"}
                  </button>
                </div>
                <div className="manage-actions-right">
                  <button type="button" onClick={handleSaveManage} className="primary-button">
                    {isZh ? "保存" : "Save"}
                  </button>
                  <button type="button" onClick={handleCancelManage} className="ghost-button">
                    {isZh ? "取消" : "Cancel"}
                  </button>
                </div>
              </div>
            ) : (
              // 普通模式下的按钮栏
              <div className="resource-actions-bar">
                <button 
                  type="button" 
                  className="action-button add-button" 
                  onClick={() => setAddResourceOpen(true)}
                >
                  <Plus size={14} />{selectedResourceGroupId ? props.text.addToGroup : props.text.add}
                </button>
                <button 
                  type="button" 
                  className="action-button edit-button" 
                  disabled={!selectedResourceId}
                  onClick={() => {
                    const selectedRes = props.customResources.find((r: CustomResource) => r.id === selectedResourceId);
                    if (selectedRes) {
                      setEditingResource(selectedRes);
                      setAddResourceOpen(true);
                    }
                  }}
                >
                  <Edit3 size={14} />{props.text.edit}
                </button>
                <button 
                  type="button" 
                  className="action-button directory-button" 
                  disabled={!selectedResourceId || (!props.customResources.find((r: CustomResource) => r.id === selectedResourceId)?.path && !selectedResourceId.startsWith("userdict-"))}
                  onClick={() => {
                    let filePath: string | undefined;
                    // 判断是用户字典还是自定义资源
                    if (selectedResourceId?.startsWith("userdict-")) {
                      // 用户字典：从ID中提取路径
                      filePath = selectedResourceId.replace("userdict-", "");
                    } else {
                      // 自定义资源
                      const selectedRes = props.customResources.find((r: CustomResource) => r.id === selectedResourceId);
                      filePath = selectedRes?.path;
                    }
                    if (filePath) {
                      void openResourceDirectory(filePath);
                    }
                  }}
                >
                  <FolderOpen size={14} />{props.text.directory || (isZh ? "目录" : "Directory")}
                </button>
                <button type="button" className="action-button manage-button" onClick={startManage}>
                  <Settings size={14} />{(isZh ? "管理" : "Manage")}
                </button>
              </div>
            )}

            {/* 新建分组对话框 */}
            {showCreateGroupDialog && (
              <div className="modal-backdrop" role="presentation">
                <section className="simple-dialog" role="dialog" aria-modal="true">
                  <div className="panel-heading">
                    <div><p className="eyebrow">Group</p><h2>{isZh ? "新建分组" : "Create Group"}</h2></div>
                    <button className="icon-button" type="button" onClick={() => setShowCreateGroupDialog(false)}><X size={15} /></button>
                  </div>
                  <div className="dialog-body">
                    <div className="form-group">
                      <label>{isZh ? "分组名称" : "Group Name"}</label>
                      <input 
                        type="text" 
                        value={newGroupName} 
                        onChange={(e) => setNewGroupName(e.target.value)} 
                        placeholder={isZh ? "请输入分组名称" : "Enter group name"}
                        autoFocus
                      />
                    </div>
                  </div>
                  <div className="dialog-actions">
                    <button className="ghost-button" type="button" onClick={() => setShowCreateGroupDialog(false)}>{props.text.cancel}</button>
                    <button 
                      className="primary-button" 
                      type="button" 
                      onClick={() => {
                        if (newGroupName.trim()) {
                          const newGroup = {
                            id: `group-${Date.now()}`,
                            name: newGroupName.trim(),
                            resourceIds: [...selectedIds],
                            expanded: true
                          };
                          setGroups(prev => [newGroup, ...prev]);
                          setManageResources(prev => prev.filter(r => !selectedIds.includes(r.id)));
                          setSelectedIds([]);
                          setNewGroupName("");
                          setShowCreateGroupDialog(false);
                        }
                      }}
                      disabled={!newGroupName.trim()}
                    >
                      {props.text.save}
                    </button>
                  </div>
                </section>
              </div>
            )}
            {/* 移动到分组对话框 */}
            {showMoveToGroupDialog && groups.length > 0 && (
              <div className="modal-backdrop" role="presentation">
                <section className="simple-dialog" role="dialog" aria-modal="true">
                  <div className="panel-heading">
                    <div><p className="eyebrow">Group</p><h2>{isZh ? "移动到分组" : "Move to Group"}</h2></div>
                    <button className="icon-button" type="button" onClick={() => setShowMoveToGroupDialog(false)}><X size={15} /></button>
                  </div>
                  <div className="dialog-body">
                    <div className="form-group">
                      <label>{isZh ? "选择分组" : "Select Group"}</label>
                      <select id="group-select">
                        <option key="ungrouped" value="">{isZh ? "无分组" : "Ungrouped"}</option>
                        {groups.map(group => (
                          <option key={group.id} value={group.id}>{group.name}</option>
                        ))}
                      </select>
                    </div>
                  </div>
                  <div className="dialog-actions">
                    <button className="ghost-button" type="button" onClick={() => setShowMoveToGroupDialog(false)}>{props.text.cancel}</button>
                    <button 
                      className="primary-button" 
                      type="button" 
                      onClick={() => {
                        const selectElement = document.getElementById("group-select") as HTMLSelectElement;
                        const targetGroupId = selectElement.value;
                        if (targetGroupId) {
                          setGroups(prev => {
                            return prev.map(group => {
                              if (group.id === targetGroupId) {
                                // 添加到目标分组（确保不重复）
                                const newResourceIds = [...new Set([...group.resourceIds, ...selectedIds])];
                                return { ...group, resourceIds: newResourceIds };
                              }
                              // 从其他分组中移除
                              const newResourceIds = group.resourceIds.filter(id => !selectedIds.includes(id));
                              return { ...group, resourceIds: newResourceIds };
                            });
                          });
                          setManageResources(prev => prev.filter(r => !selectedIds.includes(r.id)));
                        } else {
                          // 移动到无分组：只需从所有分组中移除
                          setGroups(prev => {
                            return prev.map(group => {
                              const newResourceIds = group.resourceIds.filter(id => !selectedIds.includes(id));
                              return { ...group, resourceIds: newResourceIds };
                            });
                          });
                        }
                        setSelectedIds([]);
                        setShowMoveToGroupDialog(false);
                      }}
                    >
                      {props.text.save}
                    </button>
                  </div>
                </section>
              </div>
            )}
          </div>
        )}
        
        {/* 内置资源 */}
        {activeTab === "builtin" && (
          <div className="resource-tab-panel">
            <div className="resource-list">
              {props.filteredResources.map((resource) => (
                <ResourceRow
                  key={resource.path}
                  name={resource.name}
                  meta={`${resourceKindLabel(resource.kind, props.text)} · ${formatSize(resource.size)}`}
                  description={resourceDescription(resource, props.text)}
                  onUse={() => props.useResource(resource)}
                  onPreview={canPreviewResource(resource) ? () => void previewResource(resource) : undefined}
                  useText={props.text.use}
                  previewText={props.text.preview}
                />
              ))}
            </div>
          </div>
        )}
      </div>

      {showExportDialog && (
        <div className="modal-backdrop" role="presentation">
          <section className="simple-dialog" role="dialog" aria-modal="true">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Export</p>
                <h2>{isZh ? "导出分组" : "Export Groups"}</h2>
              </div>
              <button 
                className="icon-button" 
                type="button" 
                onClick={() => setShowExportDialog(false)}
              >
                <X size={15} />
              </button>
            </div>
            <div className="dialog-body">
              {/* 类型选择 */}
              <div className="export-type-row">
                <button 
                  className={`export-type-btn ${exportType === 'preset' ? 'active' : ''}`}
                  onClick={() => {
                    setExportType('preset');
                    setSelectedExportGroups([]);
                  }}
                >
                  {isZh ? "自定义预设" : "Custom Presets"}
                </button>
                <button 
                  className={`export-type-btn ${exportType === 'custom' ? 'active' : ''}`}
                  onClick={() => {
                    setExportType('custom');
                    setSelectedExportGroups([]);
                  }}
                >
                  {isZh ? "自定义资源" : "Custom Resources"}
                </button>
              </div>

              {/* 导出名称输入 */}
              <div className="export-name-input">
                <label>{isZh ? "导出名称" : "Export Name"}</label>
                <input 
                  type="text" 
                  value={exportName}
                  onChange={(e) => setExportName(e.target.value)}
                  placeholder={isZh ? "输入导出名称" : "Enter export name"}
                />
              </div>
              
              {/* 分组列表 */}
              <div className="checkbox-list">
                {exportType === 'preset' ? (
                  props.presetGroups.map(group => (
                    <label key={group.id} className="group-checkbox-item">
                      <input 
                        type="checkbox" 
                        checked={selectedExportGroups.includes(group.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedExportGroups([...selectedExportGroups, group.id]);
                          } else {
                            setSelectedExportGroups(selectedExportGroups.filter(id => id !== group.id));
                          }
                        }}
                      />
                      <span className="group-name">{group.name}</span>
                      <span className="group-count"> ({group.presetIds?.length || 0})</span>
                    </label>
                  ))
                ) : (
                  groups.map(group => (
                    <label key={group.id} className="group-checkbox-item">
                      <input 
                        type="checkbox" 
                        checked={selectedExportGroups.includes(group.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedExportGroups([...selectedExportGroups, group.id]);
                          } else {
                            setSelectedExportGroups(selectedExportGroups.filter(id => id !== group.id));
                          }
                        }}
                      />
                      <span className="group-name">{group.name}</span>
                      <span className="group-count"> ({group.resourceIds?.length || 0})</span>
                    </label>
                  ))
                )}
              </div>
            </div>
            <div className="dialog-actions">
              {selectedExportGroups.length > 0 && (
                <div className="export-summary">
                  <div>{isZh ? "已选" : "Selected"} {selectedExportGroups.length} {isZh ? "个分组" : "groups"}</div>
                  <div>{isZh ? "包含" : "Contains"} {exportFileCount} {isZh ? "个文件资源" : "file resources"} ({formatSize(exportTotalSize)})</div>
                </div>
              )}
              <button 
                className="ghost-button" 
                type="button" 
                onClick={() => setShowExportDialog(false)}
              >
                {props.text.cancel}
              </button>
              <button 
                className="primary-button" 
                type="button" 
                onClick={handleExport}
                disabled={selectedExportGroups.length === 0}
              >
                {isZh ? "导出" : "Export"}
              </button>
            </div>
          </section>
        </div>
      )}
      {showImportDialog && (
        <div className="modal-backdrop" role="presentation">
          <section className="simple-dialog" role="dialog" aria-modal="true">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Import</p>
                <h2>{isZh ? "导入分组" : "Import Groups"}</h2>
              </div>
              <button 
                className="icon-button" 
                type="button" 
                onClick={() => setShowImportDialog(false)}
              >
                <X size={15} />
              </button>
            </div>
            <div className="dialog-body">
              <p>{isZh ? "请选择需要导入的预设或资源：" : "Please select the presets or resources you wish to import:"}</p>
              <button 
                className="primary-button" 
                type="button" 
                onClick={handleImportSelectZip}
              >
                {isZh ? "选择压缩文件" : "Select Zip File"}
              </button>
              <button 
                className="primary-button" 
                type="button" 
                onClick={handleImportSelectFolder}
              >
                {isZh ? "选择文件夹" : "Select Folder"}
              </button>
            </div>
            <div className="dialog-actions">
              <button 
                className="ghost-button" 
                type="button" 
                onClick={() => setShowImportDialog(false)}
              >
                {props.text.cancel}
              </button>
            </div>
          </section>
        </div>
      )}
      {showImportPreview && importPreviewData && (
        <div className="modal-backdrop" role="presentation">
          <section className="simple-dialog import-preview-dialog" role="dialog" aria-modal="true">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Preview</p>
                <h2>{isZh ? "导入预览" : "Import Preview"}</h2>
              </div>
              <button 
                className="icon-button" 
                type="button" 
                onClick={() => setShowImportPreview(false)}
              >
                <X size={15} />
              </button>
            </div>
            <div className="dialog-body">
              <div className="preview-summary">
                <div>
                  <strong>{isZh ? "类型：" : "Type: "}</strong>
                  {importPreviewData.type === 'preset' ? (isZh ? "预设" : "Presets") : (isZh ? "资源" : "Resources")}
                </div>
                <div><strong>{isZh ? "分组数量：" : "Groups: "}</strong>{importPreviewData.groupCount || importPreviewData.group_count || 0}</div>
                <div><strong>{isZh ? "项目数量：" : "Items: "}</strong>{importPreviewData.itemCount || importPreviewData.item_count || 0}</div>
              </div>
              
              <div className="preview-groups">
                <div><strong>{isZh ? "分组列表：" : "Group List:"}</strong></div>
                {importPreviewData.groups.map(group => {
                  console.log('Group:', group); // 添加调试日志
                  return (
                    <div key={group.id} className="preview-group-item">
                      <span className="group-name">{group.name}</span>
                      <span className="group-count"> ({(group as any).itemCount || (group as any).item_count || 0} {isZh ? "个项目" : "items"})</span>
                    </div>
                  );
                })}
              </div>
            </div>
            <div className="dialog-actions">
              <button 
                className="ghost-button" 
                type="button" 
                onClick={() => setShowImportPreview(false)}
              >
                {props.text.cancel}
              </button>
              <button 
                className="primary-button" 
                type="button" 
                onClick={handleImportConfirm}
              >
                {isZh ? "确认导入" : "Confirm Import"}
              </button>
            </div>
          </section>
        </div>
      )}
      {isConflictDialogOpen && (
        <div className="modal-backdrop">
          <section className="simple-dialog conflict-dialog">
            {/* 头部 */}
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Conflict</p>
                <h2>{isZh ? "检测到冲突" : "Conflicts Detected"}</h2>
              </div>
              <button 
                className="icon-button" 
                type="button" 
                onClick={() => handleConflictAction(null)}
              >
                <X size={15} />
              </button>
            </div>
            
            {/* 内容区域 */}
            <div className="dialog-body">
              <p>{isZh ? "以下项目已存在，选择处理方式：" : "The following items already exist. Choose how to handle:"}</p>
              <div className="conflict-list">
                {(() => {
                  // 1. 创建分组映射
                  const groupedConflicts: Record<string, ConflictInfo[]> = {};
                  const groups: ConflictInfo[] = [];
                  const presets: ConflictInfo[] = [];
                  
                  // 2. 分离分组和预设
                  conflictData.forEach(c => {
                    if (c.type === 'group') {
                      groups.push(c);
                      const groupName = c.existingName || c.name;
                      groupedConflicts[groupName] = [];
                    } else {
                      presets.push(c);
                    }
                  });
                  
                  // 3. 将预设分配到分组
                  presets.forEach(p => {
                    // 获取预设所属的分组名称
                    const presetGroupName = p.groupName || p.groupId;
                    
                    // 如果预设属于某个分组，并且该分组在冲突列表中
                    if (presetGroupName && groupedConflicts[presetGroupName]) {
                      groupedConflicts[presetGroupName].push(p);
                    } else {
                      // 回退：如果没有分组信息或分组不在冲突列表中，放到第一个分组
                      if (groups.length > 0) {
                        const firstGroupName = groups[0].existingName || groups[0].name;
                        groupedConflicts[firstGroupName].push(p);
                      }
                    }
                  });
                  
                  // 4. 渲染
                  return groups.map((group, gIndex) => {
                    const groupName = group.existingName || group.name;
                    const groupPresets = groupedConflicts[groupName] || [];
                    
                    return (
                      <div key={gIndex} className="conflict-group">
                        <div className="conflict-group-header">
                          <span className="conflict-group-name">{groupName}</span>
                          <span className="conflict-status">{isZh ? "（已存在）" : " (Exists)"}</span>
                        </div>
                        {groupPresets.length > 0 && (
                          <div className="conflict-preset-list">
                            {groupPresets.map((preset, pIndex) => (
                              <div key={pIndex} className="conflict-preset-item">
                                <span className="preset-bullet">·</span>
                                <span className="preset-name">{preset.name}</span>
                                <span className="conflict-status">{isZh ? "（已存在）" : " (Exists)"}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  });
                })()}
              </div>
            </div>
            
            {/* 操作按钮 */}
            <div className="dialog-actions">
              <button className="ghost-button" type="button" onClick={() => handleConflictAction(null)}>
                {isZh ? "取消" : "Cancel"}
              </button>
              <button className="warning-button" type="button" onClick={() => handleConflictAction('skip')}>
                {isZh ? "跳过冲突" : "Skip Conflicts"}
              </button>
              <button className="primary-button" type="button" onClick={() => handleConflictAction('merge')}>
                {isZh ? "合并" : "Merge"}
              </button>
              <button className="danger-button" type="button" onClick={() => handleConflictAction('overwrite')}>
                {isZh ? "覆盖" : "Overwrite"}
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}

function QueueTab(props: {
  items: QueueItem[];
  language: Language;
  terminalExpanded: boolean;
  setTerminalExpanded: (expanded: boolean) => void;
  paused: boolean;
  running: boolean;
  stopping: boolean;
  text: UiText;
  logs: LogPayload[];
  hashModes: HashModeInfo[];
  onClearDone: () => void;
  onPause: () => void;
  onRemove: (id: string) => void;
  onSkip: (id: string) => void;
  onRestore: (id: string) => void;
  onStart: () => void;
  onUpdateOrder: (items: QueueItem[]) => void;
  onStartSingleTask: (id: string) => void;
  onPauseSingleTask: (id: string) => void;
  latestStatus: Record<string, unknown> | null;
  simpleMode: boolean;
  setSimpleMode: (simple: boolean) => void;
  onUpdateItem: (items: QueueItem[]) => void;
}) {
  const labels = queueText(props.language);
  const [detailItem, setDetailItem] = useState<QueueItem | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [isManaging, setIsManaging] = useState(false);
  const terminalExpanded = props.terminalExpanded;
  const setTerminalExpanded = props.setTerminalExpanded;
  const [manageItems, setManageItems] = useState<QueueItem[]>([]);
  const [singleRunningId, setSingleRunningId] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const selectAllCheckboxRef = useRef<HTMLInputElement>(null);
  const clickTimeoutsRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const editInputRef = useRef<HTMLInputElement>(null);
  const [_clickCount, setClickCount] = useState(0);
  const clickTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // 自动滚动到运行中的任务
  useEffect(() => {
    // 当有任务正在运行时，自动滚动到该任务
    if (props.running) {
      // 等待 DOM 更新后执行滚动
      const timer = setTimeout(() => {
        const runningElement = document.querySelector(`.queue-row.running`);
        if (runningElement) {
          // 滚动到运行中的任务，使其显示在可见区域
          runningElement.scrollIntoView({ 
            behavior: 'smooth', 
            block: 'nearest',
            inline: 'start'
          });
        }
      }, 150);
      
      // 清理定时器
      return () => clearTimeout(timer);
    }
  }, [props.running, props.items]);

  const startSingleTask = (id: string) => {
    setSingleRunningId(id);
    props.onStartSingleTask(id);
  };

  const pauseSingleTask = (id: string) => {
    setSingleRunningId(null);
    props.onPauseSingleTask(id);
  };

  // 新增：监听任务状态变化，当任务完成时重置 singleRunningId
  useEffect(() => {
    // 检查队列中是否有运行中的任务
    const runningItem = props.items.find(item => item.status === "running");
    
    // 如果没有运行中的任务，但 singleRunningId 不为空，说明任务已经完成
    if (!runningItem && singleRunningId) {
      setSingleRunningId(null);
    }
  }, [props.items, singleRunningId]);

  // 进入管理模式时保存当前队列状态
  useEffect(() => {
    if (isManaging) {
      setManageItems([...props.items]);
    }
  }, [isManaging, props.items]);

  useEffect(() => {
    if (selectAllCheckboxRef.current) {
      selectAllCheckboxRef.current.indeterminate = getSelectAllState() === "indeterminate";
    }
  }, [selectedIds, manageItems, statusFilter, searchQuery]);  // 添加 statusFilter 和 searchQuery 作为依赖

  // 切换选择状态
  const toggleSelect = (id: string) => {
    setSelectedIds(prev => {
      if (prev.includes(id)) {
        return prev.filter(itemId => itemId !== id);
      } else {
        return [...prev, id];
      }
    });
  };

  // 获取过滤后的可选择项（管理模式下使用）
  const getFilteredSelectableItems = () => {
    return manageItems.filter(item => {
      // 过滤状态（只保留可选择的状态）
      if (item.status !== "pending" && item.status !== "skipped" && item.status !== "stopped") {
        return false;
      }
      // 过滤状态下拉框
      if (statusFilter && item.status !== statusFilter) {
        return false;
      }
      // 过滤搜索输入框
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const nameMatch = item.name?.toLowerCase().includes(query);
        const idMatch = item.id.toLowerCase().includes(query);
        if (!nameMatch && !idMatch) {
          return false;
        }
      }
      return true;
    });
  };

  // 全选
  const selectAll = () => {
    const filteredSelectableItems = getFilteredSelectableItems();
    setSelectedIds(filteredSelectableItems.map(item => item.id));
  };

  // 取消全选
  const deselectAll = () => {
    setSelectedIds([]);
  };

  // 判断全选状态
  const getSelectAllState = (): "checked" | "unchecked" | "indeterminate" => {
    const filteredSelectableItems = getFilteredSelectableItems();
    if (filteredSelectableItems.length === 0) return "unchecked";
    
    // 计算已选中的过滤后项数量
    const selectedFilteredItems = filteredSelectableItems.filter(item => selectedIds.includes(item.id));
    
    if (selectedFilteredItems.length === 0) return "unchecked";
    if (selectedFilteredItems.length === filteredSelectableItems.length) return "checked";
    return "indeterminate";
  };

  // 切换全选状态
  const toggleSelectAll = () => {
    const selectAllState = getSelectAllState();
    if (selectAllState === "checked") {
      deselectAll();
    } else {
      selectAll();
    }
  };

  // 批量置顶
  const batchMoveToTop = () => {
    setManageItems(current => {
      const selected = current.filter(item => selectedIds.includes(item.id));
      const unselected = current.filter(item => !selectedIds.includes(item.id));
      return [...selected, ...unselected];
    });
  };

  // 批量置底
  const batchMoveToBottom = () => {
    setManageItems(current => {
      const selected = current.filter(item => selectedIds.includes(item.id));
      const unselected = current.filter(item => !selectedIds.includes(item.id));
      return [...unselected, ...selected];
    });
  };

  // 批量上移
  const batchMoveUp = () => {
    setManageItems(current => {
      const newItems = [...current];
      // 获取所有选中项的索引
      const selectedIndices = [...selectedIds]
        .map(id => newItems.findIndex(item => item.id === id))
        .filter(idx => idx >= 0);
      
      if (selectedIndices.length === 0) return newItems;
      
      // 找到选中项的最小和最大索引
      const minIdx = Math.min(...selectedIndices);
      const maxIdx = Math.max(...selectedIndices);
      
      // 如果最上面的选中项已经在顶部，则无法上移
      if (minIdx === 0) return newItems;
      
      // 将选中块整体向上移动一位
      const temp = newItems[minIdx - 1];
      for (let i = minIdx; i <= maxIdx; i++) {
        newItems[i - 1] = newItems[i];
      }
      newItems[maxIdx] = temp;
      
      return newItems;
    });
  };

  // 批量下移
  const batchMoveDown = () => {
    setManageItems(current => {
      const newItems = [...current];
      // 获取所有选中项的索引
      const selectedIndices = [...selectedIds]
        .map(id => newItems.findIndex(item => item.id === id))
        .filter(idx => idx >= 0);
      
      if (selectedIndices.length === 0) return newItems;
      
      // 找到选中项的最小和最大索引
      const minIdx = Math.min(...selectedIndices);
      const maxIdx = Math.max(...selectedIndices);
      
      // 如果最下面的选中项已经在底部，则无法下移
      if (maxIdx === newItems.length - 1) return newItems;
      
      // 将选中块整体向下移动一位
      const temp = newItems[maxIdx + 1];
      for (let i = maxIdx; i >= minIdx; i--) {
        newItems[i + 1] = newItems[i];
      }
      newItems[minIdx] = temp;
      
      return newItems;
    });
  };

  // 批量删除
  const batchRemove = () => {
    setManageItems(current => 
      current.filter(item => !selectedIds.includes(item.id) || item.status === "running")
    );
    setSelectedIds([]);
  };

  // 取消管理
  const handleCancelManage = () => {
    setSelectedIds([]);
    setIsManaging(false);
  };

  // 置顶
  const moveToTop = (id: string) => {
    setManageItems((current) => {
      const item = current.find((i) => i.id === id);
      if (!item) return current;
      return [item, ...current.filter((i) => i.id !== id)];
    });
  };

  // 置底
  const moveToBottom = (id: string) => {
    setManageItems((current) => {
      const item = current.find((i) => i.id === id);
      if (!item) return current;
      return [...current.filter((i) => i.id !== id), item];
    });
  };

  // 上移
  const moveUp = (id: string) => {
    setManageItems((current) => {
      const index = current.findIndex((i) => i.id === id);
      if (index <= 0) return current;
      const newItems = [...current];
      [newItems[index - 1], newItems[index]] = [newItems[index], newItems[index - 1]];
      return newItems;
    });
  };

  // 下移
  const moveDown = (id: string) => {
    setManageItems((current) => {
      const index = current.findIndex((i) => i.id === id);
      if (index >= current.length - 1) return current;
      const newItems = [...current];
      [newItems[index], newItems[index + 1]] = [newItems[index + 1], newItems[index]];
      return newItems;
    });
  };

  // 完成调整
  const handleSaveManage = () => {
    // 可以参与排序的任务：pending, skipped, stopped（等待启动、已跳过、已暂停）
    const sortableItems = manageItems.filter(item => 
      item.status === "pending" || item.status === "skipped" || item.status === "stopped"
    );
    // 不参与排序的任务：running, finished, failed（运行中、已完成、已失败）
    const nonSortableItems = props.items.filter(item => 
      item.status === "running" || item.status === "finished" || item.status === "failed"
    );
    const result = [...nonSortableItems, ...sortableItems];
    props.onUpdateOrder(result);
    setManageItems(result);
    setSelectedIds([]);
    setIsManaging(false);
  };

  const validItems = useMemo(() => {
    // 管理模式下也需要应用过滤条件
    const baseItems = isManaging ? manageItems : props.items;
    
    // 应用状态过滤和搜索过滤
    const filteredBaseItems = baseItems.filter(item => {
      // 状态过滤
      if (statusFilter && item.status !== statusFilter) {
        return false;
      }
      // 搜索过滤
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        // 搜索任务名称
        if (item.config.taskName?.toLowerCase().includes(query)) {
          return true;
        }
        // 搜索哈希模式名称
        const hashModeInfo = props.hashModes.find(m => String(m.mode) === item.config.hashMode);
        if (hashModeInfo?.name.toLowerCase().includes(query) || hashModeInfo?.category.toLowerCase().includes(query)) {
          return true;
        }
        // 搜索攻击模式名称
        const attackModeName = attackModeLabel(item.config.attackMode, props.text);
        if (attackModeName.toLowerCase().includes(query)) {
          return true;
        }
        // 搜索字典路径（提取文件名）
        if (item.config.dictionaryPath) {
          const dictName = item.config.dictionaryPath.split(/[\\/]/).pop()?.toLowerCase();
          if (dictName?.includes(query)) {
            return true;
          }
        }
        // 搜索掩码
        if (item.config.mask?.toLowerCase().includes(query)) {
          return true;
        }
        return false;
      }
      return true;
    });
    
    // 过滤有效状态
    return filteredBaseItems.filter(item => 
      ["pending", "running", "skipped", "finished", "failed", "stopped"].includes(item.status)
    );
  }, [isManaging, manageItems, props.items, statusFilter, searchQuery, props.hashModes, props.text]);

  const groupColorMap = useMemo(() => {
      const map: Record<string, string> = {};
      // 收集所有唯一的任务组（按首次出现顺序）
      const seenGroups = new Set<string>();
      const uniqueGroups: string[] = [];
      
      for (const item of validItems) {
        if (item.groupId && !seenGroups.has(item.groupId)) {
          uniqueGroups.push(item.groupId);
          seenGroups.add(item.groupId);
        }
      }
      
      // 为每个任务组分配颜色（第一个任务组使用 group-color-1）
      uniqueGroups.forEach((groupId, idx) => {
        map[groupId] = `group-color-${(idx % 2) + 1}`;
      });
      
      return map;
    }, [validItems]);

  return (
    <div className="tab-content queue-tab">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Task Queue</p>
          <h2>{labels.title}</h2>
        </div>
      </div>

      <div className="queue-filter-bar">
        <select className="status-filter" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="">{props.text.allStatus} ({props.items.length})</option>
          <option value="running">{props.language === "zh" ? "运行中" : "Running"} ({props.items.filter(item => item.status === "running").length})</option>
          <option value="pending">{props.language === "zh" ? "等待" : "Pending"} ({props.items.filter(item => item.status === "pending").length})</option>
          <option value="stopped">{props.language === "zh" ? "已暂停" : "Stopped"} ({props.items.filter(item => item.status === "stopped").length})</option>
          <option value="skipped">{props.language === "zh" ? "已跳过" : "Skipped"} ({props.items.filter(item => item.status === "skipped").length})</option>
          <option value="failed">{props.language === "zh" ? "已失败" : "Failed"} ({props.items.filter(item => item.status === "failed").length})</option>
        </select>
        <input 
          type="text" 
          className="search-input" 
          placeholder={props.text.searchPlaceholder}
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
        <label className="simple-mode-toggle">
          <input type="checkbox" checked={props.simpleMode} onChange={(e) => props.setSimpleMode(e.target.checked)} />
          <span className="slider-wrapper">
            <span className="slider"></span>
          </span>
          <span className="toggle-label">{props.language === "zh" ? "简约模式" : "Simple Mode"}</span>
        </label>
        <button className={`ghost-button ${isManaging ? "danger-button" : ""}`} type="button" 
                onClick={() => isManaging ? handleSaveManage() : setIsManaging(true)}>
          <Settings size={14} />{isManaging ? props.text.finishManage : props.text.manageQueue}
        </button>
      </div>

      <div className="queue-list">
        {validItems.length ? validItems.map((item, index) => {
          const groupColor = groupColorMap[item.groupId || ""] || "";
          
          const isSelectable = item.status === "pending" || item.status === "skipped" || item.status === "stopped";
          const isSelected = selectedIds.includes(item.id);
          
          const handleMouseDown = (event: React.MouseEvent) => {
            if (event.button !== 0) return;
            const target = event.target as HTMLElement;
            if (target.closest('.task-name') || target.closest('.task-name-editor') || target.closest('button')) {
              return;
            }
            const timeoutId = setTimeout(() => {
              clickTimeoutsRef.current.delete(item.id);
              
              // 只有在超时后（不是双击）才执行单击逻辑
              const selection = window.getSelection();
              const hasSelection = selection && selection.toString().trim().length > 0;
              
              if (!hasSelection) {
                if (isManaging && isSelectable) {
                  toggleSelect(item.id);
                } else {
                  setDetailItem(item);
                }
              }
            }, 300);
            clickTimeoutsRef.current.set(item.id, timeoutId);
          };

          const handleMouseUp = (event: React.MouseEvent) => {
            const target = event.target as HTMLElement;
            
            // 如果点击的是任务名称，不执行行级别的单击逻辑
            if (target.closest('.task-name') || target.closest('.task-name-editor')) {
              return;
            }
            
            const timeoutId = clickTimeoutsRef.current.get(item.id);
            if (timeoutId) {
              clearTimeout(timeoutId);
              clickTimeoutsRef.current.delete(item.id);
              
              const selection = window.getSelection();
              const hasSelection = selection && selection.toString().trim().length > 0;
              
              if (!hasSelection) {
                if (isManaging && isSelectable) {
                  toggleSelect(item.id);
                } else {
                  setDetailItem(item);
                }
              }
            }
          };

          // 任务名称单击处理
          const handleTaskNameClick = (event: React.MouseEvent, _item: QueueItem) => {
            event.stopPropagation();
            // 标题区域单击不做任何操作（只保留双击编辑功能）
          };

          // 任务名称双击处理
          const handleTaskNameDoubleClick = (event: React.MouseEvent, item: QueueItem) => {
            event.stopPropagation();
            
            // 清除计时器，阻止单击逻辑执行
            if (clickTimeoutRef.current) {
              clearTimeout(clickTimeoutRef.current);
              clickTimeoutRef.current = null;
            }
            
            // 重置点击计数
            setClickCount(0);
            
            // 双击：编辑名称（运行中的任务不允许编辑）
            if (item.status === "running") return;
            
            setEditingId(item.id);
            setEditName(item.name?.trim() || item.id);
            
            setTimeout(() => {
              editInputRef.current?.focus();
              editInputRef.current?.select();
            }, 0);
          };

          // 保存编辑的名称
          const handleNameSave = () => {
            if (!editingId || !editName.trim()) return;
            
            // 清除所有可能的单击计时器，防止触发详情弹窗
            clickTimeoutsRef.current.forEach((timeoutId, id) => {
              clearTimeout(timeoutId);
              clickTimeoutsRef.current.delete(id);
            });
            
            // 如果使用了 clickTimeoutRef（参考历史页面的方式），也需要清除
            if (clickTimeoutRef.current) {
              clearTimeout(clickTimeoutRef.current);
              clickTimeoutRef.current = null;
            }
            
            // 获取当前编辑的队列项
            const item = props.items.find(i => i.id === editingId);
            
            // 更新队列
            props.onUpdateItem(props.items.map(i => 
              i.id === editingId ? { ...i, name: editName.trim() } : i
            ));
            
            // 如果任务已经有 taskId（已经运行过），保存到名称映射以便历史页面使用
            if (item?.taskId) {
              saveTaskName(item.taskId, editName.trim());
            }
            
            setEditingId(null);
            setEditName("");
          };

          // 取消编辑
          const handleNameCancel = () => {
            // 清除所有可能的单击计时器
            clickTimeoutsRef.current.forEach((timeoutId, id) => {
              clearTimeout(timeoutId);
              clickTimeoutsRef.current.delete(id);
            });
            
            if (clickTimeoutRef.current) {
              clearTimeout(clickTimeoutRef.current);
              clickTimeoutRef.current = null;
            }
            
            setEditingId(null);
            setEditName("");
          };

          // 键盘事件处理
          const handleNameKeyDown = (event: React.KeyboardEvent) => {
            if (event.key === "Enter") {
              handleNameSave();
            } else if (event.key === "Escape") {
              handleNameCancel();
            }
          };

          const handleMouseLeave = () => {
            const timeoutId = clickTimeoutsRef.current.get(item.id);
            if (timeoutId) {
              clearTimeout(timeoutId);
              clickTimeoutsRef.current.delete(item.id);
            }
          };
          
          return (
          <div className={`queue-row ${item.status} ${isSelected ? "selected" : ""} ${isManaging && isSelectable ? "selectable" : ""}`} 
            key={item.id} 
            role="button" 
            tabIndex={0} 
            onMouseDown={handleMouseDown} 
            onMouseUp={handleMouseUp} 
            onMouseLeave={handleMouseLeave}
            onKeyDown={(event) => { 
              if (event.key === "Enter") {
                if (isManaging && isSelectable) {
                  toggleSelect(item.id);
                } else {
                  setDetailItem(item);
                }
              } 
            }}>
            {isManaging && isSelectable && (
              <div className="queue-checkbox">
                <input 
                  type="checkbox" 
                  checked={isSelected} 
                  onClick={(e) => e.stopPropagation()}  // 新增
                  onChange={(e) => { e.stopPropagation(); toggleSelect(item.id); }} 
                />
              </div>
            )}
            <div className={`queue-index ${groupColor}`}>{index + 1}</div>
            <div className="queue-main">
              <div className="task-header">
                <span className={`status-badge ${item.status}`}>{queueStatusLabel(item.status, props.language)}</span>
                {editingId === item.id ? (
                  <div className="task-name-editor">
                    <input
                      ref={editingId === item.id ? editInputRef : null}
                      type="text"
                      value={editName}
                      onChange={(e) => setEditName(e.target.value)}
                      onKeyDown={(e) => { handleNameKeyDown(e); e.stopPropagation(); }}
                      onBlur={handleNameSave}
                      onClick={(e) => e.stopPropagation()}
                    />
                  </div>
                ) : (
                  <strong 
                    className="task-name" 
                    onClick={(e) => handleTaskNameClick(e, item)}
                    onDoubleClick={(e) => handleTaskNameDoubleClick(e, item)}
                  >
                    {item.name?.trim() || item.id}
                  </strong>
                )}
              </div>
              {!props.simpleMode && (
                <>
                  <div className="task-meta">
                    <span className="meta-tag time-tag">{formatTaskDate(item.createdAt)}</span>
                    <span className="meta-tag hash-mode-tag">{props.hashModes.find(m => String(m.mode) === item.config.hashMode)?.name || `Mode ${item.config.hashMode}`}</span>
                    <span className="meta-tag attack-mode-tag">{attackModeLabel(item.config.attackMode, props.text)}</span>
                  </div>
                  <code className="resource-info">
                    {extractResourceInfo(item.config, item.candidates, props.language === "zh", item.isEstimated)}
                  </code>
                </>
              )}
              {item.error && <em>{item.error}</em>}
              {(item.status === "running" || item.status === "stopped") && (
                <TaskProgressBar item={item} latestStatus={props.latestStatus} language={props.language} />
              )}
            </div>
            <div className="queue-actions">
              {isManaging && isSelectable && (
                <>
                  <button type="button" onClick={(event) => { event.stopPropagation(); moveToTop(item.id); }} title="置顶">
                    <ArrowUpToLine size={14} />
                  </button>
                  <button type="button" onClick={(event) => { event.stopPropagation(); moveToBottom(item.id); }} title="置底">
                    <ArrowDownToLine size={14} />
                  </button>
                  <button type="button" onClick={(event) => { event.stopPropagation(); moveUp(item.id); }} title="上移">
                    <ChevronUp size={14} />
                  </button>
                  <button type="button" onClick={(event) => { event.stopPropagation(); moveDown(item.id); }} title="下移">
                    <ChevronDown size={14} />
                  </button>
                </>
              )}

              {!isManaging && (item.status === "pending" || item.status === "failed" || item.status === "stopped") && (
                <button 
                  type="button" 
                  onClick={(event) => { event.stopPropagation(); startSingleTask(item.id); }}
                  disabled={props.running || props.stopping || (!!singleRunningId && singleRunningId !== item.id)}
                >
                  {props.language === "zh" ? "启动" : "Start"}
                </button>
              )}
              {!isManaging && item.status === "running" && singleRunningId === item.id && (
                <button 
                  type="button" 
                  onClick={(event) => { event.stopPropagation(); pauseSingleTask(item.id); }}
                  disabled={props.stopping}
                >
                  {props.language === "zh" ? "暂停" : "Pause"}
                </button>
              )}

              {!isManaging && (item.status === "pending" || item.status === "stopped") && <button type="button" onClick={(event) => { event.stopPropagation(); props.onSkip(item.id); }}>{labels.skip}</button>}
              {!isManaging && item.status === "skipped" && <button type="button" onClick={(event) => { event.stopPropagation(); props.onRestore(item.id); }}>{labels.restore}</button>}
              {!isManaging && item.status !== "running" && <button type="button" onClick={(event) => { event.stopPropagation(); props.onRemove(item.id); }}>{labels.remove}</button>}
            </div>
          </div>
          )
        }) : <div className="empty-state">{labels.empty}</div>}
      </div>
      {detailItem && <QueueDetailDialog item={detailItem} language={props.language} text={props.text} onClose={() => setDetailItem(null)} />}
      
      {isManaging ? (
        <div className="manage-actions-bar">
          <div className="manage-actions-left">
            <label className="select-all-label">
              <input 
                ref={selectAllCheckboxRef}
                type="checkbox" 
                checked={getSelectAllState() === "checked"}
                onChange={toggleSelectAll}
              />
              <span>{props.language === "zh" ? "全选" : "Select All"}</span>
            </label>
          </div>
          <div className="manage-actions-center">
            <button type="button" onClick={batchMoveToTop} disabled={selectedIds.length === 0}>
              <ArrowUpToLine size={14} />{props.language === "zh" ? "置顶" : "Top"}
            </button>
            <button type="button" onClick={batchMoveToBottom} disabled={selectedIds.length === 0}>
              <ArrowDownToLine size={14} />{props.language === "zh" ? "置底" : "Bottom"}
            </button>
            <button type="button" onClick={batchMoveUp} disabled={selectedIds.length === 0}>
              <ChevronUp size={14} />{props.language === "zh" ? "上移" : "Up"}
            </button>
            <button type="button" onClick={batchMoveDown} disabled={selectedIds.length === 0}>
              <ChevronDown size={14} />{props.language === "zh" ? "下移" : "Down"}
            </button>
            <button type="button" onClick={batchRemove} disabled={selectedIds.length === 0} className="danger-button">
              <Trash2 size={14} />{props.language === "zh" ? "删除" : "Delete"}
            </button>
          </div>
          <div className="manage-actions-right">
            <button type="button" onClick={handleSaveManage} className="primary-button">
              {props.language === "zh" ? "保存" : "Save"}
            </button>
            <button type="button" onClick={handleCancelManage} className="ghost-button">
              {props.language === "zh" ? "取消" : "Cancel"}
            </button>
          </div>
        </div>
      ) : (
        <div className={terminalExpanded ? "run-console-card expanded" : "run-console-card collapsed"}>
          <div className="run-console-header">
            <div className="line-title">
              <Terminal size={16} />
              <span>{props.text.liveTerminal}</span>
              <strong>{props.running ? props.text.running : props.text.waitingStart}</strong>
            </div>
            <button 
              className="ghost-button terminal-toggle-button" 
              type="button" 
              onClick={() => setTerminalExpanded(!terminalExpanded)}
            >
              {terminalExpanded ? props.text.collapse : props.text.expand}
            </button>
          </div>
          {terminalExpanded && <TerminalOutput logs={props.logs} text={props.text} />}
        </div>
      )}
    </div>
  );
}

function QueueDetailDialog(props: {
  item: QueueItem;
  language: Language;
  text: UiText;
  onClose: () => void;
}) {
  const config = props.item.config;
  const zh = props.language === "zh";
  const [hashContent, setHashContent] = useState<string | null>(null);

  useEffect(() => {
    async function loadHashContent() {
      if (config.hashText?.trim()) {
        setHashContent(config.hashText);
        return;
      }
      if (config.hashFile) {
        try {
          const response = await invoke<FilePreviewResponse>("preview_text_file", { 
            path: config.hashFile, 
            allowFull: true 
          });
          setHashContent(response.content || "-");
        } catch {
          setHashContent("-");
        }
      } else {
        setHashContent("-");
      }
    }
    void loadHashContent();
  }, [config.hashText, config.hashFile]);

  const charsetText = [
    (config.charsetFile1 || config.customCharset1) ? `-1 ${config.charsetFile1 || config.customCharset1}` : "",
    (config.charsetFile2 || config.customCharset2) ? `-2 ${config.charsetFile2 || config.customCharset2}` : "",
    (config.charsetFile3 || config.customCharset3) ? `-3 ${config.charsetFile3 || config.customCharset3}` : "",
    (config.charsetFile4 || config.customCharset4) ? `-4 ${config.charsetFile4 || config.customCharset4}` : "",
  ].filter(Boolean).join("\n") || "-";
  const isComboMode = config.attackMode === 1;
  const isWpaMode = config.hashMode === "22000";
  const wpaInfo = isWpaMode && hashContent ? parseWpaHashInfo(hashContent) : null;
  const rows = [
    [zh ? "任务状态" : "Status", queueStatusLabel(props.item.status, props.language)],
    [zh ? "Hash 类型" : "Hash Mode", `-m ${config.hashMode}`],
    ...(wpaInfo && wpaInfo.essids.length > 0 ? [[zh ? "ESSID" : "ESSID", wpaInfo.essids.join("\n")]] : []),
    ...(wpaInfo && wpaInfo.bssids.length > 0 ? [[zh ? "BSSID" : "BSSID", wpaInfo.bssids.join("\n")]] : []),
    [zh ? "攻击方式" : "Attack Mode", `${attackModeLabel(config.attackMode, props.text)} (-a ${config.attackMode === 9 ? "0 / template" : config.attackMode})`],
    [zh ? "Hash 文件" : "Hash File", config.hashFile || "-"],
    ...(isComboMode ? [
      [zh ? "左字典" : "Left Dictionary", config.dictionaryPath || "-"],
      [zh ? "右字典" : "Right Dictionary", config.dictionaryPath2 || "-"],
    ] : [
      [zh ? "字典文件" : "Dictionary", config.dictionaryPath || "-"],
    ]),
    ...(isComboMode ? [
      [zh ? "左规则" : "Left Rule", config.leftRule || "-"],
      [zh ? "右规则" : "Right Rule", config.rightRule || "-"],
    ] : [
      [zh ? "规则" : "Rules", config.rulePaths?.length ? config.rulePaths.join("\n") : "-"],
    ]),
    [zh ? "掩码" : "Mask", config.attackMode === 3 ? (config.maskFile || config.mask || "-") : (config.mask || "-")],
    [zh ? "递增掩码" : "Increment", config.increment ? `${config.incrementMin || "-"} ~ ${config.incrementMax || "-"}` : "-"],
    [zh ? "模板前缀" : "Template Prefix", config.templatePrefixMask || "-"],
    [zh ? "模板后缀" : "Template Suffix", config.templateSuffixMask || "-"],
    [zh ? "自定义字符" : "Custom Charsets", charsetText],
    [zh ? "性能/设备" : "Performance / Devices", `-w ${config.workloadProfile ?? 3}${config.deviceTypes?.length ? `, -D ${config.deviceTypes.join(",")}` : ""}${config.deviceIds ? `, -d ${config.deviceIds}` : ""}`],
    [zh ? "创建时间" : "Created", formatDateTime(props.item.createdAt)],
    [zh ? "开始时间" : "Started", formatDateTime(props.item.startedAt)],
    [zh ? "结束时间" : "Finished", formatDateTime(props.item.finishedAt)],
    [zh ? "后端任务 ID" : "Backend Task ID", props.item.taskId || "-"],
  ];

  return createPortal(
    <div className="modal-backdrop" role="presentation">
      <section className="queue-detail-modal" role="dialog" aria-modal="true" aria-label={zh ? "队列任务详情" : "Queue Task Detail"}>
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Queue Detail</p>
            <h2>{props.item.name}</h2>
            <span>{queueStatusLabel(props.item.status, props.language)}</span>
          </div>
          <button className="icon-button" type="button" onClick={props.onClose}><X size={15} /></button>
        </div>

        <div className="queue-detail-grid">
          {rows.map(([label, value]) => (
            <div className="queue-detail-row" key={label}>
              <span>{label}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </div>

        <section className="queue-detail-block">
          <div className="line-title"><Hash size={15} /><span>{zh ? "Hash 内容" : "Hash Text"}</span></div>
          <pre>{hashContent ?? "..."}</pre>
        </section>

        <section className="queue-detail-block">
          <div className="line-title"><Terminal size={15} /><span>{props.text.commandPreview}</span></div>
          <pre>{buildPreview(config)}</pre>
        </section>

        {props.item.error && (
          <section className="queue-detail-block warn">
            <div className="line-title"><AlertTriangle size={15} /><span>{props.text.errorLabel}</span></div>
            <pre>{props.item.error}</pre>
          </section>
        )}
      </section>
    </div>,
    document.body,
  );
}


function HistoryTab(props: {
  analyzeLog: (taskId: string) => void;
  aiRunningTaskIds: string[];
  taskLog: ResultsResponse | null;
  readTaskLogFor: (id?: string) => void;
  copyResults: () => void;
  deleteTask: (id: string) => void;
  exportResults: () => void;
  loadTask: (task: TaskManifest) => void;
  openTaskDir: () => void;
  readResultsFor: (id?: string) => void;
  rerunTask: (id: string) => void;
  restoreTask: (id: string) => void;
  results: ResultsResponse | null;
  selectedTask?: TaskManifest;
  selectedTaskId: string;
  setSelectedTaskId: (id: string) => void;
  tasks: TaskManifest[];
  language: Language;
  text: UiText;
  hashModes: HashModeInfo[];
  statusFilter: string;
  setStatusFilter: (status: string) => void;
  searchQuery: string;
  setSearchQuery: (query: string) => void;
  simpleMode: boolean;
  setSimpleMode: (simple: boolean) => void;
}) {
  const [detailTask, setDetailTask] = useState<TaskManifest | null>(null);
  const [showLogView, setShowLogView] = useState(false);
  const [isManaging, setIsManaging] = useState(false);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [manageItems, setManageItems] = useState<TaskManifest[]>([]);
  const [originalItems, setOriginalItems] = useState<TaskManifest[]>([]);
  const [localSelectedId, setLocalSelectedId] = useState(props.selectedTaskId);
  const [copiedTaskId, setCopiedTaskId] = useState<string | null>(null);
  const [clickCount, setClickCount] = useState(0);
  const clickTimeoutRef = useRef<number | null>(null);
  const selectAllCheckboxRef = useRef<HTMLInputElement>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const editInputRef = useRef<HTMLInputElement>(null);
  const [_localTasks, setLocalTasks] = useState<TaskManifest[]>([]);


  const filteredTasks = useMemo(() => {
    return props.tasks.filter(task => {
      // 状态过滤
      if (props.statusFilter) {
        if (props.statusFilter === "error") {
          if (task.status !== "error" && task.status !== "backend-error") {
            return false;
          }
        } else if (task.status !== props.statusFilter) {
          return false;
        }
      }
      // 搜索过滤
      if (props.searchQuery) {
        const query = props.searchQuery.toLowerCase();
        const taskName = (task.taskName || task.taskId).toLowerCase();
        const hashMode = (props.hashModes.find(m => String(m.mode) === task.config.hashMode)?.name || `Mode ${task.config.hashMode}`).toLowerCase();
        const attackMode = attackModeLabel(task.config.attackMode, props.text).toLowerCase();
        if (!taskName.includes(query) && !hashMode.includes(query) && !attackMode.includes(query)) {
          return false;
        }
      }
      return true;
    });
  }, [props.tasks, props.statusFilter, props.searchQuery, props.hashModes, props.text]);

  // 进入管理模式时保存当前任务状态
  useEffect(() => {
    if (isManaging) {
      setOriginalItems([...props.tasks]);
      setManageItems([...props.tasks]);
      setSelectedIds([]);
    }
  }, [isManaging, props.tasks]);

  // 同步全选复选框的 indeterminate 状态
  useEffect(() => {
    if (selectAllCheckboxRef.current) {
      selectAllCheckboxRef.current.indeterminate = getSelectAllState() === "indeterminate";
    }
  }, [selectedIds, manageItems, props.statusFilter, props.searchQuery]);

  // 切换选择状态
  const toggleSelect = (id: string) => {
    setSelectedIds(prev => {
      if (prev.includes(id)) {
        return prev.filter(itemId => itemId !== id);
      } else {
        return [...prev, id];
      }
    });
  };

  const getFilteredSelectableItems = () => {
    // 管理模式下使用 manageItems，否则使用缓存的 filteredTasks
    if (!isManaging) {
      return filteredTasks;
    }
    
    // 管理模式下仍需过滤 manageItems
    return manageItems.filter(task => {
      if (props.statusFilter) {
        if (props.statusFilter === "error") {
          if (task.status !== "error" && task.status !== "backend-error") {
            return false;
          }
        } else if (task.status !== props.statusFilter) {
          return false;
        }
      }
      if (props.searchQuery) {
        const query = props.searchQuery.toLowerCase();
        const taskName = (task.taskName || task.taskId).toLowerCase();
        const hashMode = (props.hashModes.find(m => String(m.mode) === task.config.hashMode)?.name || `Mode ${task.config.hashMode}`).toLowerCase();
        const attackMode = attackModeLabel(task.config.attackMode, props.text).toLowerCase();
        if (!taskName.includes(query) && !hashMode.includes(query) && !attackMode.includes(query)) {
          return false;
        }
      }
      return true;
    });
  };

  // 全选
  const selectAll = () => {
    const filteredSelectableItems = getFilteredSelectableItems();
    setSelectedIds(filteredSelectableItems.map(item => item.taskId));
  };

  // 取消全选
  const deselectAll = () => {
    setSelectedIds([]);
  };

  // 判断全选状态
  const getSelectAllState = () => {
    const filteredSelectableItems = getFilteredSelectableItems();
    if (filteredSelectableItems.length === 0) return "unchecked";
    
    // 计算已选中的过滤后项数量
    const selectedFilteredItems = filteredSelectableItems.filter(item => selectedIds.includes(item.taskId));
    
    if (selectedFilteredItems.length === 0) return "unchecked";
    if (selectedFilteredItems.length === filteredSelectableItems.length) return "checked";
    return "indeterminate";
  };

  // 切换全选状态
  const toggleSelectAll = () => {
    const selectAllState = getSelectAllState();
    if (selectAllState === "checked") {
      deselectAll();
    } else {
      selectAll();
    }
  };

  // 批量删除（本地）
  const batchRemove = () => {
    setManageItems(current => {
      return current.filter(item => !selectedIds.includes(item.taskId));
    });
  };

  // 完成管理（保存）
  const handleSaveManage = () => {
    // 找出被删除的任务（原始列表中有但当前列表中没有的）
    const deletedIds = originalItems
      .map(item => item.taskId)
      .filter(id => !manageItems.some(item => item.taskId === id));
    
    // 真正删除这些任务
    deletedIds.forEach(id => {
      props.deleteTask(id);
    });
    setSelectedIds([]);
    setIsManaging(false);
  };

  // 取消管理
  const handleCancelManage = () => {
    // 恢复到原始状态
    setManageItems([...originalItems]);
    setSelectedIds([]);
    setIsManaging(false);
  };

  function select(id: string) {
    if (localSelectedId === id) {
      // 立即更新本地状态
      setLocalSelectedId("");
      // 异步更新父组件状态
      props.setSelectedTaskId("");
    } else {
      // 立即更新本地状态，实现快速响应
      setLocalSelectedId(id);
      // 异步更新父组件状态
      props.setSelectedTaskId(id);
      // 异步读取结果
      void props.readResultsFor(id);
    }
  }
  return (
    <div className="tab-content history-tab">
      {showLogView && props.selectedTask ? (
        // 日志视图 - 只显示 Run Log 窗口，全屏显示
        <section className="log-detail full-screen">
          <div className="log-detail-head">
            <div><p className="eyebrow">Run Log</p><h2>{props.selectedTask.taskName || props.selectedTask.taskId}</h2><span>{shortPath(props.selectedTask.paths.logPath)}</span></div>
            <div className="log-actions">
              <button className="primary-button ai-analyze-button" type="button" onClick={() => props.analyzeLog(props.selectedTask!.taskId)} disabled={props.aiRunningTaskIds.includes(props.selectedTask.taskId)}><Bot size={16} />{props.aiRunningTaskIds.includes(props.selectedTask.taskId) ? props.text.aiAnalyzing : props.text.aiAnalyze}</button>
              <button className="secondary-button" type="button" onClick={() => setShowLogView(false)}><X size={16} />{props.text.close}</button>
            </div>
          </div>
          <pre className="log-window task-log-output">{props.taskLog?.content || props.text.noLogs}</pre>
        </section>
      ) : (
      // 历史视图
      <div className="history-container">
        <div className="history-filter-bar">
          <select className="status-filter" value={props.statusFilter} onChange={(e) => props.setStatusFilter(e.target.value)}>
            <option value="">{props.text.allStatus} ({props.tasks.length})</option>
            <option value="cracked">{props.text.statusCracked} ({props.tasks.filter(task => task.status === "cracked").length})</option>
            <option value="exhausted">{props.text.statusExhausted} ({props.tasks.filter(task => task.status === "exhausted").length})</option>
            <option value="error">{props.text.statusError} ({props.tasks.filter(task => task.status === "error" || task.status === "backend-error").length})</option>
          </select>
          <input 
            type="text" 
            className="search-input" 
            placeholder={props.text.searchPlaceholder}
            value={props.searchQuery}
            onChange={(e) => props.setSearchQuery(e.target.value)}
          />
          <label className="simple-mode-toggle">
            <input type="checkbox" checked={props.simpleMode} onChange={(e) => props.setSimpleMode(e.target.checked)} />
            <span className="slider-wrapper">
              <span className="slider"></span>
            </span>
            <span className="toggle-label">{props.language === "zh" ? "简约模式" : "Simple Mode"}</span>
          </label>
          <button 
            className={`ghost-button ${isManaging ? "danger-button" : ""}`} 
            type="button" 
            onClick={() => isManaging ? handleSaveManage() : setIsManaging(true)}
          >
            <Settings size={14} />{isManaging ? props.text.finishManage : props.text.manageHistory}
          </button>
        </div>
        <div className="history-layout">
          <div className="task-list">
            {(() => {
              // 过滤任务
              let filteredTasks = props.tasks;
              
              // 状态过滤
              if (props.statusFilter) {
                filteredTasks = filteredTasks.filter(task => {
                  if (props.statusFilter === "error") {
                    // 错误状态包括 error 和 backend-error
                    return task.status === "error" || task.status === "backend-error";
                  }
                  return task.status === props.statusFilter;
                });
              }
              
              // 搜索过滤
              if (props.searchQuery) {
                const query = props.searchQuery.toLowerCase();
                filteredTasks = filteredTasks.filter(task => {
                  const taskName = (task.taskName || task.taskId).toLowerCase();
                  const hashMode = (props.hashModes.find(m => String(m.mode) === task.config.hashMode)?.name || `Mode ${task.config.hashMode}`).toLowerCase();
                  const attackMode = attackModeLabel(task.config.attackMode, props.text).toLowerCase();
                  const resourceInfo = extractResourceInfo(task.config).toLowerCase();
                  return taskName.includes(query) || hashMode.includes(query) || attackMode.includes(query) || resourceInfo.includes(query);
                });
              }
              
              return filteredTasks;
            })().length ? (() => {
              let filteredTasks = isManaging ? manageItems : props.tasks;
              
              // 状态过滤
              if (props.statusFilter) {
                filteredTasks = filteredTasks.filter(task => {
                  if (props.statusFilter === "error") {
                    // 错误状态包括 error 和 backend-error
                    return task.status === "error" || task.status === "backend-error";
                  }
                  return task.status === props.statusFilter;
                });
              }
              
              // 搜索过滤
              if (props.searchQuery) {
                const query = props.searchQuery.toLowerCase();
                filteredTasks = filteredTasks.filter(task => {
                  const taskName = (task.taskName || task.taskId).toLowerCase();
                  const hashMode = (props.hashModes.find(m => String(m.mode) === task.config.hashMode)?.name || `Mode ${task.config.hashMode}`).toLowerCase();
                  const attackMode = attackModeLabel(task.config.attackMode, props.text).toLowerCase();
                  const resourceInfo = extractResourceInfo(task.config, task.config.candidates, true).toLowerCase();
                  return taskName.includes(query) || hashMode.includes(query) || attackMode.includes(query) || resourceInfo.includes(query);
                });
              }
              
              return filteredTasks.map((task) => {
                const isSelected = selectedIds.includes(task.taskId);
                const handleClick = () => {
                  if (isManaging) {
                    toggleSelect(task.taskId);  // 管理模式：切换选中状态
                  } else {
                    select(task.taskId);        // 非管理模式：打开详情
                  }
                };

                const handleSelectTask = () => {
                  if (isManaging) {
                    toggleSelect(task.taskId);
                  } else {
                    select(task.taskId);
                  }
                };

                const handleTaskNameDoubleClick = (task: TaskManifest) => {
                  setEditingId(task.taskId);
                  setEditName(task.taskName?.trim() || task.taskId);
                  
                  setTimeout(() => {
                    editInputRef.current?.focus();
                    editInputRef.current?.select();
                  }, 0);
                };

                // 新增：保存编辑的名称
                const handleNameSave = () => {
                  if (!editingId || !editName.trim()) return;
                  
                  // 更新本地任务列表中的名称
                  setLocalTasks(prev => prev.map((t: TaskManifest) => 
                    t.taskId === editingId ? { ...t, taskName: editName.trim() } : t
                  ));
                  
                  // 保存到任务名称映射（持久化存储）
                  saveTaskName(editingId, editName.trim());
                  
                  setEditingId(null);
                  setEditName("");
                };

                // 新增：取消编辑
                const handleNameCancel = () => {
                  setEditingId(null);
                  setEditName("");
                };

                // 新增：键盘事件处理
                const handleNameKeyDown = (event: React.KeyboardEvent) => {
                  if (event.key === "Enter") {
                    handleNameSave();
                  } else if (event.key === "Escape") {
                    handleNameCancel();
                  }
                };

                return (
                  <div className={`task-row ${!isManaging && localSelectedId === task.taskId ? "active" : ""} ${isSelected ? "selected" : ""} ${isManaging ? "selectable" : ""}`} key={task.taskId} role="button" tabIndex={0} onClick={handleClick}>
                    {isManaging && (
                      <div className="task-checkbox">
                        <input 
                          type="checkbox" 
                          checked={isSelected}
                          onClick={(e) => e.stopPropagation()}
                          onChange={(e) => { e.stopPropagation(); toggleSelect(task.taskId); }}
                        />
                      </div>
                    )}
                    <div className="task-main">
                      <div className="task-header">
                        <span className={`status-badge ${task.status}`}>{statusLabel(task.status, props.language)}</span>
                        {editingId === task.taskId ? (
                          <div className="task-name-editor">
                            <input
                              ref={editingId === task.taskId ? editInputRef : null}
                              type="text"
                              value={editName}
                              onChange={(e) => setEditName(e.target.value)}
                              onKeyDown={(e) => { handleNameKeyDown(e); e.stopPropagation(); }}
                              onBlur={handleNameSave}
                              onClick={(e) => e.stopPropagation()}
                            />
                          </div>
                        ) : (
                          <strong 
                            className="task-name"
                            onClick={(e) => { e.stopPropagation(); handleSelectTask(); }}
                            onDoubleClick={(e) => { e.stopPropagation(); handleTaskNameDoubleClick(task); }}
                          >
                            {task.taskName || task.taskId}
                          </strong>
                        )}
                      </div>

                      {task.status === "cracked" && task.extractedPasswords && task.extractedPasswords.length > 0 && (
                        <div className="task-password-display">
                          <span className="password-label">{props.language === "zh" ? "密码" : "Password"}:</span>
                          <span 
                            className="password-value"
                            onClick={(e) => {
                              e.stopPropagation();
                              if (clickTimeoutRef.current) clearTimeout(clickTimeoutRef.current);
                              setClickCount(prev => prev + 1);
                              clickTimeoutRef.current = window.setTimeout(() => {
                                if (clickCount === 1) {
                                  handleSelectTask();
                                }
                                setClickCount(0);
                                clickTimeoutRef.current = null;
                              }, 300);
                            }}
                            onDoubleClick={(e) => {
                              e.stopPropagation();
                              if (clickTimeoutRef.current) {
                                clearTimeout(clickTimeoutRef.current);
                                clickTimeoutRef.current = null;
                              }
                              setClickCount(0);
                              navigator.clipboard.writeText(task.extractedPasswords?.[0] ?? '');
                              setCopiedTaskId(task.taskId);
                              setTimeout(() => setCopiedTaskId(null), 2000);
                            }}
                            title={props.language === "zh" ? "双击复制密码" : "Double-click to copy password"}
                          >
                            {task.extractedPasswords[0] + (copiedTaskId === task.taskId ? (props.language === "zh" ? "  (✅ 已复制)" : "  (✅ Copied)") : "")}
                          </span>
                        </div>
                      )}

                      {!props.simpleMode && (
                        <>
                          <div className="task-meta">
                            <span className="meta-tag time-tag">{formatTaskDate(task.createdAt)}</span>
                            <span className="meta-tag hash-mode-tag">{props.hashModes.find(m => String(m.mode) === task.config.hashMode)?.name || `Mode ${task.config.hashMode}`}</span>
                            <span className="meta-tag attack-mode-tag">{attackModeLabel(task.config.attackMode, props.text)}</span>
                          </div>
                          <code className="resource-info">{extractResourceInfo(task.config, task.config.candidates ?? undefined, props.language === "zh", task.config.isEstimated)}</code>
                        </>
                      )}
                    </div>
                    {!isManaging && (
                      <div className="task-actions">
                        <button type="button" onClick={(event) => { event.stopPropagation(); setDetailTask(task); }}><FileText size={14} />{props.text.detail}</button>
                        <button type="button" onClick={() => props.loadTask(task)}>{props.text.load}</button>
                        {/* 恢复按钮：完成状态（破解、错误、已耗尽）不显示 */}
                        {!["cracked", "error", "backend-error", "exhausted"].includes(task.status) && <button type="button" disabled={!task.canRestore} onClick={() => props.restoreTask(task.taskId)}>{props.text.restore}</button>}
                        <button type="button" onClick={() => props.deleteTask(task.taskId)}><Trash2 size={14} /></button>
                      </div>
                    )}
                  </div>
                );
            });

            })() : <div className="empty-state">{props.text.noHistory}</div>}
          </div>
          {!isManaging && (
            <section className="history-detail">
              {props.selectedTask ? (
                <>
                  <div className="history-detail-head">
                    <div><p className="eyebrow">Task Result</p><h2>{props.selectedTask.taskName || props.selectedTask.taskId}</h2><span>{statusLabel(props.selectedTask.status, props.language)}</span></div>
                    <div className="result-actions">
                      <button type="button" onClick={() => { setShowLogView(true); props.readTaskLogFor(props.selectedTask!.taskId); }}><FileText size={15} />{props.text.log}</button>
                      <button type="button" onClick={props.copyResults} disabled={!props.results?.content}><Copy size={15} />{props.text.copy}</button>
                      <button type="button" onClick={props.exportResults} disabled={!props.results?.content}><Download size={15} />{props.text.export}</button>
                      <button type="button" onClick={props.openTaskDir}><FolderOpen size={15} />{props.text.directory}</button>
                      <button type="button" onClick={() => props.readResultsFor()}><RefreshCcw size={15} />{props.text.refresh}</button>
                    </div>
                  </div>
                  <pre className="results-output">{props.results?.content || props.text.noResults}</pre>
                </>
              ) : (
                <div className="empty-state history-empty">{props.text.selectHistoryForResult}</div>
              )}
            </section>
          )}
          {isManaging && (
            <div className="manage-actions-bar">
              <div className="manage-actions-left">
                <label className="select-all-label">
                  <input 
                    ref={selectAllCheckboxRef}
                    type="checkbox" 
                    checked={getSelectAllState() === "checked"}
                    onChange={toggleSelectAll}
                  />
                  <span>{props.language === "zh" ? "全选" : "Select All"}</span>
                </label>
              </div>
              <div className="manage-actions-center">
                <button type="button" onClick={batchRemove} disabled={selectedIds.length === 0} className="danger-button">
                  <Trash2 size={14} />{props.language === "zh" ? "删除" : "Delete"}
                </button>
              </div>
              <div className="manage-actions-right">
                <button type="button" onClick={handleSaveManage} className="primary-button">
                  {props.language === "zh" ? "保存" : "Save"}
                </button>
                <button type="button" onClick={handleCancelManage} className="ghost-button">
                  {props.language === "zh" ? "取消" : "Cancel"}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    )}
      {detailTask && <HistoryDetailDialog task={detailTask} language={props.language} text={props.text} onClose={() => setDetailTask(null)} />}
    </div>
  );
}

function HistoryDetailDialog(props: {
  task: TaskManifest;
  language: Language;
  text: UiText;
  onClose: () => void;
}) {
  const config = props.task.config;
  const zh = props.language === "zh";
  const [hashContent, setHashContent] = useState<string | null>(null);
  
  useEffect(() => {
    async function loadHashContent() {
      if (config.hashText?.trim()) {
        setHashContent(config.hashText);
        return;
      }
      if (config.hashFile) {
        try {
          const response = await invoke<FilePreviewResponse>("preview_text_file", { 
            path: config.hashFile, 
            allowFull: true 
          });
          setHashContent(response.content || "-");
        } catch {
          setHashContent("-");
        }
      } else {
        setHashContent("-");
      }
    }
    void loadHashContent();
  }, [config.hashText, config.hashFile]);
  
  const charsetText = [
    (config.charsetFile1 || config.customCharset1) ? `-1 ${config.charsetFile1 || config.customCharset1}` : "",
    (config.charsetFile2 || config.customCharset2) ? `-2 ${config.charsetFile2 || config.customCharset2}` : "",
    (config.charsetFile3 || config.customCharset3) ? `-3 ${config.charsetFile3 || config.customCharset3}` : "",
    (config.charsetFile4 || config.customCharset4) ? `-4 ${config.charsetFile4 || config.customCharset4}` : "",
  ].filter(Boolean).join("\n") || "-";
  const isComboMode = config.attackMode === 1;
  const isWpaMode = config.hashMode === "22000";
  const wpaInfo = isWpaMode && hashContent ? parseWpaHashInfo(hashContent) : null;
  const rows = [
    [zh ? "任务状态" : "Status", statusLabel(props.task.status, props.language)],
    [zh ? "Hash 类型" : "Hash Mode", `-m ${config.hashMode}`],
    ...(wpaInfo && wpaInfo.essids.length > 0 ? [[zh ? "ESSID" : "ESSID", wpaInfo.essids.join("\n")]] : []),
    ...(wpaInfo && wpaInfo.bssids.length > 0 ? [[zh ? "BSSID" : "BSSID", wpaInfo.bssids.join("\n")]] : []),
    [zh ? "攻击方式" : "Attack Mode", `${attackModeLabel(config.attackMode, props.text)} (-a ${config.attackMode === 9 ? "0 / template" : config.attackMode})`],
    [zh ? "Hash 文件" : "Hash File", config.hashFile || "-"],
    ...(isComboMode ? [
      [zh ? "左字典" : "Left Dictionary", config.dictionaryPath || "-"],
      [zh ? "右字典" : "Right Dictionary", config.dictionaryPath2 || "-"],
    ] : [
      [zh ? "字典文件" : "Dictionary", config.dictionaryPath || "-"],
    ]),
    ...(isComboMode ? [
      [zh ? "左规则" : "Left Rule", config.leftRule || "-"],
      [zh ? "右规则" : "Right Rule", config.rightRule || "-"],
    ] : [
      [zh ? "规则" : "Rules", config.rulePaths?.length ? config.rulePaths.join("\n") : "-"],
    ]),
    [zh ? "掩码" : "Mask", config.attackMode === 3 ? (config.maskFile || config.mask || "-") : (config.mask || "-")],
    [zh ? "递增掩码" : "Increment", config.increment ? `${config.incrementMin || "-"} ~ ${config.incrementMax || "-"}` : "-"],
    [zh ? "模板前缀" : "Template Prefix", config.templatePrefixMask || "-"],
    [zh ? "模板后缀" : "Template Suffix", config.templateSuffixMask || "-"],
    [zh ? "自定义字符" : "Custom Charsets", charsetText],
    [zh ? "性能/设备" : "Performance / Devices", `-w ${config.workloadProfile ?? 3}${config.deviceTypes?.length ? `, -D ${config.deviceTypes.join(",")}` : ""}${config.deviceIds ? `, -d ${config.deviceIds}` : ""}`],
    [zh ? "退出码" : "Exit Code", props.task.exitCode !== null ? String(props.task.exitCode) : "-"],
    [zh ? "退出原因" : "Exit Reason", props.task.exitReason || "-"],
    [zh ? "创建时间" : "Created", formatDateTime(props.task.createdAt)],
    [zh ? "开始时间" : "Started", formatDateTime(props.task.startedAt)],
    [zh ? "结束时间" : "Finished", formatDateTime(props.task.endedAt)],
    [zh ? "后端任务 ID" : "Backend Task ID", props.task.taskId || "-"],
  ];

  return createPortal(
    <div className="modal-backdrop" role="presentation">
      <section className="queue-detail-modal" role="dialog" aria-modal="true" aria-label={zh ? "历史任务详情" : "History Task Detail"}>
        <div className="panel-heading">
          <div>
            <p className="eyebrow">History Detail</p>
            <h2>{props.task.taskName || props.task.taskId}</h2>
            <span>{statusLabel(props.task.status, props.language)}</span>
          </div>
          <button className="icon-button" type="button" onClick={props.onClose}><X size={15} /></button>
        </div>

        <div className="queue-detail-grid">
          {rows.map(([label, value]) => (
            <div className="queue-detail-row" key={label}>
              <span>{label}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </div>

        <section className="queue-detail-block">
          <div className="line-title"><Hash size={15} /><span>{zh ? "Hash 内容" : "Hash Text"}</span></div>
          <pre>{hashContent ?? "..."}</pre>
        </section>

        <section className="queue-detail-block">
          <div className="line-title"><Terminal size={15} /><span>{props.text.commandPreview}</span></div>
          <pre>{props.task.commandPreview}</pre>
        </section>
      </section>
    </div>,
    document.body,
  );
}


function HelpDialog(props: {
  config: AiHashConsultConfig;
  text: UiText;
  onClose: () => void;
  onStartAi: (config: AiHashConsultConfig) => Promise<void>;
}) {
  const [draft, setDraft] = useState<AiHashConsultConfig>(() => normalizeHelpConfig(props.config));
  const [message, setMessage] = useState("");
  const [asking, setAsking] = useState(false);
  const tutorials = [
    { title: props.text.helpDictionaryTitle, body: props.text.helpDictionaryBody },
    { title: props.text.helpMaskTitle, body: props.text.helpMaskBody },
    { title: props.text.helpHybridTitle, body: props.text.helpHybridBody },
    { title: props.text.helpTemplateTitle, body: props.text.helpTemplateBody },
    { title: props.text.helpRuleTitle, body: props.text.helpRuleBody },
  ];

  async function chooseHashTxt() {
    const selected = await open({ multiple: false, directory: false });
    if (typeof selected === "string") {
      setDraft((current) => ({ ...current, hashFile: selected, hashText: "" }));
    }
  }

  async function askAi() {
    setAsking(true);
    setMessage("");
    try {
      await props.onStartAi(draft);
      setMessage(props.text.aiStartedInWindow);
      props.onClose();
    } catch (err) {
      setMessage(String(err));
    } finally {
      setAsking(false);
    }
  }

  function updateDraft(field: keyof AiHashConsultConfig, value: string) {
    setDraft((current) => ({ ...current, [field]: value }));
  }

  return createPortal(
    <div className="modal-backdrop" role="presentation">
      <section className="help-modal" role="dialog" aria-modal="true" aria-label={props.text.helpTitle}>
        <div className="panel-heading">
          <div><p className="eyebrow">{props.text.helpSubtitle}</p><h2>{props.text.helpTitle}</h2></div>
          <button className="icon-button" type="button" onClick={props.onClose}><X size={15} /></button>
        </div>
        <div className="help-layout">
          <section className="help-guides">
            <div className="line-title"><span>{props.text.attackTutorials}</span></div>
            {tutorials.map((item) => (
              <article className="help-guide-card" key={item.title}>
                <strong>{item.title}</strong>
                <p>{item.body}</p>
              </article>
            ))}
          </section>
          <section className="help-ai-panel">
            <div className="line-title"><span>{props.text.aiHashAdvisor}</span><strong>{props.text.useCurrentConfig}</strong></div>
            <div className="help-config-grid">
              <label className="field"><span>{props.text.hashMode}</span><input value={draft.hashMode ?? ""} onChange={(event) => updateDraft("hashMode", event.currentTarget.value)} /></label>
              <label className="field"><span>{props.text.file}</span><input value={draft.hashFile ?? ""} onChange={(event) => updateDraft("hashFile", event.currentTarget.value)} /></label>
            </div>
            <button className="ghost-button" type="button" onClick={chooseHashTxt}><FileText size={15} />{props.text.chooseHashTxt}</button>
            <label className="field">
              <span>{props.text.hashInput}</span>
              <textarea value={draft.hashText ?? ""} onChange={(event) => updateDraft("hashText", event.currentTarget.value)} placeholder={props.text.hashInputPlaceholder} spellCheck={false} />
            </label>
            <label className="field">
              <span>{props.text.aiQuestion}</span>
              <textarea value={draft.question ?? ""} onChange={(event) => updateDraft("question", event.currentTarget.value)} placeholder={props.text.aiQuestionPlaceholder} />
            </label>
            {message && <div className="settings-test warn">{message}</div>}
            <div className="settings-actions">
              <button className="primary-button" type="button" onClick={() => void askAi()} disabled={asking}><Bot size={16} />{asking ? props.text.aiThinking : props.text.askAi}</button>
            </div>
            <pre className="help-ai-answer">{props.text.aiStartedInWindow}</pre>
          </section>
        </div>
      </section>
    </div>,
    document.body,
  );
}

function AiSettingsDialog(props: {
  language: Language;
  setLanguage: (language: Language) => void;
  text: UiText;
  settings: AiSettings;
  hashcatPathStatus: HashcatPathStatus | null;
  onClose: () => void;
  onHashcatPathChange: (path: string) => Promise<void>;
  onOpenUpdate: () => void;
  onSave: (settings: AiSettings) => void;
}) {
  const [draft, setDraft] = useState<AiSettings>(() => normalizeAiSettings(props.settings));
  const [models, setModels] = useState<string[]>([]);
  const [testing, setTesting] = useState(false);
  const [message, setMessage] = useState("");
  function updateDraft(field: keyof AiSettings, value: string) {
    setDraft((current) => ({ ...current, [field]: value }));
  }
  async function testConnection() {
    setTesting(true);
    setMessage("");
    try {
      const response = await invoke<AiModelsResponse>("list_ai_models", { settings: draft });
      setModels(response.models);
      setMessage(props.text.connectionOk.replace("{count}", String(response.models.length)));
      if (!draft.model && response.models[0]) updateDraft("model", response.models[0]);
    } catch (err) {
      setModels([]);
      setMessage(String(err));
    } finally {
      setTesting(false);
    }
  }
  async function chooseHashcatInstallDir() {
    const selected = await open({ multiple: false, directory: true });
    if (typeof selected === "string") await props.onHashcatPathChange(selected);
  }
  return (
    <div className="modal-backdrop" role="presentation">
      <section className="settings-modal" role="dialog" aria-modal="true" aria-label={props.text.settingsTitle}>
        <div className="panel-heading"><div><p className="eyebrow">Settings</p><h2>{props.text.settingsTitle}</h2></div><button className="icon-button" type="button" onClick={props.onClose}><X size={15} /></button></div>
        <label className="field">
          <span>{props.text.language}</span>
          <select value={props.language} onChange={(event) => props.setLanguage(event.currentTarget.value as Language)}>
            <option value="zh">{props.text.chinese}</option>
            <option value="en">{props.text.english}</option>
          </select>
        </label>
        <label className="field"><span>Base URL</span><input value={draft.baseUrl} onChange={(event) => updateDraft("baseUrl", event.currentTarget.value)} placeholder="https://api.openai.com/v1" /></label>
        <label className="field"><span>API Key</span><input type="password" value={draft.apiKey} onChange={(event) => updateDraft("apiKey", event.currentTarget.value)} placeholder="sk-..." /></label>
        <label className="field"><span>{props.text.model}</span><input value={draft.model} onChange={(event) => updateDraft("model", event.currentTarget.value)} placeholder="gpt-4o-mini" /></label>
        {models.length > 0 && <label className="field"><span>{props.text.availableModels}</span><select value={models.includes(draft.model) ? draft.model : ""} onChange={(event) => updateDraft("model", event.currentTarget.value)}><option value="">{props.text.chooseModel}</option>{models.map((model) => <option value={model} key={model}>{model}</option>)}</select></label>}
        <div className="settings-tool-card hashcat-path-card">
          <div>
            <strong>{props.language === "zh" ? "Hashcat 安装目录" : "Hashcat Install Folder"}</strong>
            <span title={props.hashcatPathStatus?.customInstallDir || props.hashcatPathStatus?.effectiveDir || ""}>
              {props.hashcatPathStatus?.customInstallDir
                ? props.hashcatPathStatus.customInstallDir
                : props.language === "zh" ? "默认：工具目录 resources/hashcat-current" : "Default: tool folder resources/hashcat-current"}
            </span>
            {props.hashcatPathStatus?.effectiveDir && <em>{props.language === "zh" ? "当前使用：" : "Using: "}{props.hashcatPathStatus.effectiveDir}</em>}
          </div>
          <div className="settings-card-actions">
            <button className="ghost-button" type="button" onClick={chooseHashcatInstallDir}><FolderOpen size={15} />{props.language === "zh" ? "选择" : "Choose"}</button>
            <button className="ghost-button" type="button" onClick={() => props.onHashcatPathChange("")} disabled={!props.hashcatPathStatus?.customInstallDir}>{props.language === "zh" ? "默认" : "Default"}</button>
          </div>
        </div>
        <div className="settings-tool-card">
          <div>
            <strong>{props.text.hashcatUpdate}</strong>
            <span>{props.text.hashcatUpdateHint}</span>
          </div>
          <button className="ghost-button" type="button" onClick={props.onOpenUpdate}><Download size={15} />{props.text.hashcatUpdate}</button>
        </div>
        
        {message && <div className={models.length ? "settings-test ok" : "settings-test warn"}>{message}</div>}
        <div className="settings-actions">
          <button className="ghost-button" type="button" onClick={testConnection} disabled={testing}><Bot size={16} />{testing ? props.text.testing : props.text.testConnection}</button>
          <button className="ghost-button" type="button" onClick={props.onClose}>{props.text.cancel}</button>
          <button className="primary-button" type="button" onClick={() => props.onSave(draft)}>{props.text.save}</button>
        </div>
      </section>
    </div>
  );
}

function HashcatUpdateDialog(props: {
  info: HashcatUpdateInfo | null;
  logs: HashcatUpdateEvent[];
  running: boolean;
  text: UiText;
  onCheck: () => void;
  onClose: () => void;
  onInstall: () => void;
}) {
  const status = props.info
    ? props.info.upToDate ? props.text.updateUpToDate : props.text.updateAvailable
    : props.text.updateNotChecked;
  const latestLog = props.logs[props.logs.length - 1];

  return createPortal(
    <div className="modal-backdrop" role="presentation">
      <section className="settings-modal hashcat-update-modal" role="dialog" aria-modal="true" aria-label={props.text.hashcatUpdate}>
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Hashcat Release Channel</p>
            <h2>{props.text.hashcatUpdate}</h2>
            <span>{props.text.hashcatUpdateHint}</span>
          </div>
          <button className="icon-button" type="button" onClick={props.onClose} disabled={props.running}><X size={15} /></button>
        </div>

        <div className="update-version-grid">
          <div className="update-version-card">
            <span>{props.text.updateCurrent}</span>
            <strong>{props.info?.currentVersion ?? "-"}</strong>
          </div>
          <div className="update-version-card accent">
            <span>{props.text.updateLatest}</span>
            <strong>{props.info?.latestVersion ?? "-"}</strong>
          </div>
          <div className={`update-version-card ${props.info?.upToDate ? "ok" : "warn"}`}>
            <span>Status</span>
            <strong>{props.running ? props.text.updateRunning : status}</strong>
          </div>
        </div>

        <div className="update-package-card">
          <span>{props.text.updatePackage}</span>
          <strong>{props.info?.assetName ?? "-"}</strong>
          {props.info?.releaseUrl && <button className="ghost-button" type="button" onClick={() => window.open(props.info?.releaseUrl, "_blank")}><FolderOpen size={15} />{props.text.openRelease}</button>}
        </div>

        <div className="settings-actions">
          <button className="ghost-button" type="button" onClick={props.onCheck} disabled={props.running}><RefreshCcw size={15} />{props.text.checkUpdate}</button>
          <button className="primary-button" type="button" onClick={props.onInstall} disabled={props.running || !props.info || props.info.upToDate}><Download size={15} />{props.running ? props.text.updateRunning : props.text.installUpdate}</button>
        </div>

        <div className="update-log-card">
          <div className="line-title"><Terminal size={15} /><span>{props.text.updateLog}</span></div>
          <div className="update-log-stream">
            {latestLog ? <code><span>{latestLog.phase}</span>{latestLog.line}</code> : <em>{props.text.updateNotChecked}</em>}
          </div>
        </div>
      </section>
    </div>,
    document.body,
  );
}

function AiAnalysisWindow(props: {
  canApplySuggestion: boolean;
  content: string;
  error: string;
  minimized: boolean;
  running: boolean;
  taskId: string;
  title: string;
  text: UiText;
  onApplySuggestion: () => void;
  onClose: () => void;
  onMinimize: () => void;
  onRestore: () => void;
}) {
  const outputRef = useRef<HTMLPreElement | null>(null);
  const autoFollowRef = useRef(true);

  function updateAutoFollow() {
    const output = outputRef.current;
    if (!output) return;
    const distanceToBottom = output.scrollHeight - output.scrollTop - output.clientHeight;
    autoFollowRef.current = distanceToBottom < 40;
  }

  useEffect(() => {
    const output = outputRef.current;
    if (output && autoFollowRef.current) output.scrollTop = output.scrollHeight;
  }, [props.content, props.error]);

  async function copyAnalysis() {
    const content = props.error ? `${props.content}\n\n[${props.text.errorLabel}]\n${props.error}` : props.content;
    if (content.trim()) await writeText(content);
  }

  if (props.minimized) {
    return (
      <button className="ai-mini-window" type="button" onClick={props.onRestore}>
        <Bot size={16} />
        <span>{props.running ? props.text.aiAnalyzing : props.title}</span>
      </button>
    );
  }

  return (
    <div className="ai-window-backdrop" role="presentation">
      <section className="ai-window" role="dialog" aria-modal="true" aria-label={props.title}>
        <header className="ai-window-head">
          <div>
            <p className="eyebrow">AI Analysis</p>
            <h2>{props.title}</h2>
            <span>{props.taskId || props.text.noTaskSelected}</span>
          </div>
          <div className="ai-window-actions">
            {props.canApplySuggestion && <button className="primary-button" type="button" onClick={props.onApplySuggestion}><Bot size={15} />{props.text.applyAiSuggestion}</button>}
            <button className="ghost-button" type="button" onClick={copyAnalysis} disabled={!props.content && !props.error}><Copy size={15} />{props.text.copy}</button>
            <button className="ghost-button" type="button" onClick={props.onMinimize}>{props.text.minimize}</button>
            <button className="icon-button" type="button" onClick={props.onClose}><X size={16} /></button>
          </div>
        </header>
        <pre className="ai-window-output" ref={outputRef} onScroll={updateAutoFollow}>{props.content || (props.running ? props.text.aiConnecting : props.text.noAiContent)}{props.error ? `\n\n[${props.text.errorLabel}]\n${props.error}` : ""}</pre>
        <footer className="ai-window-foot"><span className={props.running ? "live-dot on" : "live-dot"} />{props.running ? props.text.aiStreaming : props.text.aiFinished}</footer>
      </section>
    </div>
  );
}
function TerminalOutput({ logs, text }: { logs: LogPayload[]; text: UiText }) {
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const element = ref.current;
    if (element) element.scrollTop = element.scrollHeight;
  }, [logs.length]);
  return (
    <div className="log-window" ref={ref}>
      {logs.length ? logs.slice(-260).map((log, index) => <p className={log.stream} key={`${log.taskId}-${index}`}><span>{log.stream}</span>{log.line}</p>) : <div className="empty-state">{text.terminalWaiting}</div>}
    </div>
  );
}

function useDropZone(onDrop: (paths: string[]) => void) {
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.currentTarget.classList.add('drag-over');
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.currentTarget.classList.remove('drag-over');
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.currentTarget.classList.remove('drag-over');
    
    const paths: string[] = [];
    // 遍历 dataTransfer.files 而不是 items
    for (let i = 0; i < e.dataTransfer.items.length; i++) {
      const item = e.dataTransfer.items[i];
      if (item.kind === 'file') {
        const file = item.getAsFile();
        // 在 Tauri 中，文件的完整路径存储在 path 属性中
        const path = (file as any)?.path || file?.name;
        if (path) {
          paths.push(path);
        }
      }
    }
    
    if (paths.length > 0) {
      onDrop(paths);
    }
  };

  return { handleDragOver, handleDragLeave, handleDrop };
}

function FileButton(props: {
  label: string;
  value: string;
  empty: string;
  onClick: () => void;
  onClear: () => void;
  clearText: string;
  useResourceText?: string;      // 新增：使用资源按钮文字
  onUseResource?: () => void;    // 新增：使用资源点击事件
  extraContent?: React.ReactNode;
  onDrop?: (paths: string[]) => void;
}) {
  const { handleDragOver, handleDragLeave, handleDrop } = useDropZone((paths) => {
    props.onDrop?.(paths);
  });
  return (
    <div className="resource-line"
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {/* 将 line-title 移动到这里 */}
      <div className="line-title">
        <span>{props.label}</span>
        {props.useResourceText && props.onUseResource && (
          <button type="button" onClick={props.onUseResource}>{props.useResourceText}</button>
        )}
        {props.extraContent}
      </div>
      <button className="file-button" type="button" onClick={props.onClick} title={props.value || props.label}>
        <FolderOpen size={15} />
        <span>{props.value ? shortPath(props.value) : props.empty}</span>
      </button>
      {props.value && <button className="clear-file-button" type="button" onClick={props.onClear}>
        <X size={13} />{props.clearText}
      </button>}
    </div>
  );
}

function ResourceRow(props: { name: string; meta: string; description: string; onUse: () => void; onPreview?: () => void; useText: string; previewText: string }) {
  return (
    <div className="resource-row">
      <div className="resource-content"><strong>{props.name}</strong><span>{props.meta}</span><em>{props.description}</em></div>
      <div className="resource-actions">
        {props.onPreview && <button type="button" onClick={props.onPreview}>{props.previewText}</button>}
        <button type="button" onClick={props.onUse}>{props.useText}</button>
      </div>
    </div>
  );
}

function ResourcePreviewDialog(props: {
  name: string;
  preview: FilePreviewResponse;
  text: UiText;
  onClose: () => void;
}) {
  return (
    <div className="modal-backdrop" role="presentation">
      <section className="resource-preview-modal" role="dialog" aria-modal="true" aria-label={props.text.resourcePreviewTitle}>
        <div className="panel-heading">
          <div>
            <p className="eyebrow">{props.text.resourcePreviewTitle}</p>
            <h2>{props.name}</h2>
            <span>{shortPath(props.preview.path)}</span>
          </div>
          <button className="icon-button" type="button" onClick={props.onClose}><X size={15} /></button>
        </div>
        {props.preview.truncated && <div className="settings-test warn">{props.text.previewTruncated.replace("{count}", String(props.preview.lineCount))}</div>}
        <div className="settings-test warn">{props.text.copiedDictionaryOnly}</div>
        <pre className="resource-preview-output">{props.preview.content || props.text.previewEmpty}</pre>
      </section>
    </div>
  );
}

function CustomResourceManager(props: {
  resources: CustomResource[];
  userDictionaries: UserDictionary[];
  text: UiText;
  onClose: () => void;
  onSave: (resource: CustomResource) => void;
  onDelete: (resource: CustomResource) => void;
  onUse: (resource: CustomResource) => void;
  onRemoveDictionary: (path: string) => void;
  editing?: CustomResource | null;
  resourcesList?: ResourceInfo[];
}) {
  const [type, setType] = useState<CustomResource["type"]>("dictionary");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [mask, setMaskValue] = useState("");
  const [prefixMask, setPrefixMask] = useState("");
  const [suffixMask, setSuffixMask] = useState("");
  const [charsetSlot, setCharsetSlot] = useState<"1" | "2" | "3" | "4">("1");
  const [charsetValue, setCharsetValue] = useState("");
  const [rulePath, setRulePath] = useState("");
  const [ruleLines, setRuleLines] = useState(0);
  const [maskPath, setMaskPath] = useState("");
  const [editing, setEditing] = useState<CustomResource | null>(null);
  const [editContent, setEditContent] = useState("");
  const [editTruncated, setEditTruncated] = useState(false);
  const [appendContent, setAppendContent] = useState("");
  const [message, setMessage] = useState("");
  const [dedupingPath, setDedupingPath] = useState("");
  const [copyToAppDir, setCopyToAppDir] = useState(false);
  const [isEditable, setIsEditable] = useState(true);
  const isZh = props.text.settingsTitle === "设置";

  function resetForm() {
    setName("");
    setDescription("");
    setMaskValue("");
    setPrefixMask("");
    setSuffixMask("");
    setCharsetSlot("1");
    setCharsetValue("");
    setRulePath("");
    setRuleLines(0);
  }

  function saveManualResource() {
    if (type === "mask" && !mask.trim() && !maskPath && !editing) return;
    if (type === "template" && !prefixMask.trim() && !suffixMask.trim()) return;
    if (type === "charset" && !charsetValue.trim()) return;
    if (type === "rule" && !rulePath && !editing) return;
    
    // 获取默认名称
    let defaultName = "";
    switch (type) {
      case "mask":
        defaultName = maskPath 
          ? maskPath.split('/').pop() || maskPath.split('\\').pop() || mask.trim()  // 使用文件名
          : mask.trim();
        break;
      case "charset":
        defaultName = `?${charsetSlot} ${charsetValue.trim()}`;
        break;
      case "rule":
        defaultName = rulePath.split('/').pop() || rulePath.split('\\').pop() || "Rules";
        break;
      case "template":
        defaultName = `${prefixMask || "<empty>"} + word + ${suffixMask || "<empty>"}`;
        break;
    }
    
    // 允许用户自定义所有类型的名称，如果用户没有输入，则使用默认名称
    let finalName = name.trim() || defaultName;
    // 如果用户没有输入名称，对于规则和掩码文件，使用从路径中提取的文件名
    if (!name.trim()) {
      if (type === "rule" && rulePath) {
        finalName = rulePath.split('/').pop() || rulePath.split('\\').pop() || "Rules";
      } else if (type === "mask" && maskPath) {
        finalName = maskPath.split('/').pop() || maskPath.split('\\').pop() || mask.trim() || "Masks";
      }
    }
    props.onSave({
      id: editing && editing.type !== "dictionary" ? editing.id : `custom-${Date.now()}`,
      type,
      name: finalName,
      description: description.trim(),
      mask: type === "mask" ? mask.trim() : undefined,
      prefixMask: type === "template" ? prefixMask.trim() : undefined,
      suffixMask: type === "template" ? suffixMask.trim() : undefined,
      charsetSlot: type === "charset" ? charsetSlot : undefined,
      charsetValue: type === "charset" ? charsetValue.trim() : undefined,
      path: type === "rule" ? rulePath : (type === "mask" ? maskPath : undefined),
      size: type === "rule" ? ruleLines : undefined,
      createdAt: editing?.createdAt ?? new Date().toISOString(),
    });
    setEditing(null);
    resetForm();
  }


  function editManualResource(resource: CustomResource) {
    setEditing(resource);
    setType(resource.type);
    setName(resource.name);
    setDescription(resource.description);
    setMaskValue(resource.mask ?? "");
    setPrefixMask(resource.prefixMask ?? "");
    setSuffixMask(resource.suffixMask ?? "");
    setCharsetSlot(resource.charsetSlot ?? "1");
    setCharsetValue(resource.charsetValue ?? "");
    setEditContent("");
    setEditTruncated(false);
    setAppendContent("");
    setMessage("");
    setRulePath(resource.path ?? "");
    setMaskPath(resource.path ?? "");
  }


  async function importDictionaryCopy() {
    // 启用多选功能
    const selected = await open({ multiple: true, directory: false });
    // 处理用户未选择或选择空的情况
    if (!selected || (Array.isArray(selected) && selected.length === 0)) return;
    
    // 统一处理单文件和多文件情况
    const files = Array.isArray(selected) ? selected : [selected];
    
    try {
      // 显示已选择的文件路径（支持中英切换）
      const fileNames = files.map(f => f.replace(/\\/g, '/').split('/').pop()).join(', ');
      setMessage(isZh ? `已选择 ${files.length} 个文件：${fileNames}` : `Selected ${files.length} files: ${fileNames}`);
      
      // 批量保存每个文件
      for (const filePath of files) {
        let imported: UserDictionary;
        
        if (copyToAppDir) {
          // 勾选：复制到软件目录
          imported = await invoke<UserDictionary>("import_custom_dictionary", { 
            source: filePath, 
            copyToAppDir: true 
          });
        } else {
          // 未勾选：直接使用原始路径
          const fileName = filePath.replace(/\\/g, '/').split('/').pop() || "dictionary.txt";
          const preview = await invoke<FilePreviewResponse>("preview_text_file", { path: filePath, allowFull: false });
          imported = {
            name: fileName,
            path: filePath,
            size: preview.fileSize,
            addedAt: new Date().toISOString(),
          };
        }

        const finalName = files.length === 1 ? (name.trim() || imported.name) : imported.name;

        props.onSave({
          id: `custom-${Date.now()}`,
          type: "dictionary",
          name: finalName,
          description: description.trim(),
          path: imported.path,
          size: imported.size,
          createdAt: new Date().toISOString(),
          isBuiltinCopy: copyToAppDir,
        });
      }
      
      resetForm();
      setCopyToAppDir(false);  // 重置勾选状态
      
      // 多文件导入完成后显示成功消息（支持中英切换）
      if (files.length > 1) {
        setMessage(isZh ? `已成功导入 ${files.length} 个字典文件` : `Successfully imported ${files.length} dictionary files`);
      }
    } catch (err) {
      setMessage(String(err));
    }
  }

  async function importMaskFile() {
    const selected = await open({ multiple: false, directory: false });
    if (typeof selected !== "string") return;
    try {
      const content = await invoke<FilePreviewResponse>("preview_text_file", { path: selected, allowFull: true });
      const masks = content.content.trim().split('\n').filter(line => line.trim());
      if (masks.length === 0) {
        setMessage(isZh ? "掩码文件为空" : "Mask file is empty");
        return;
      }
      
      // 提取文件名（兼容 Windows 和 Unix 路径）
      const fileName = selected.replace(/\\/g, '/').split('/').pop() || "Masks";
      
      // 清空之前的名称状态，确保使用文件名
      setName("");

      // 如果只有一行，保存为单个掩码；否则保存为文件路径
      if (masks.length === 1) {
        props.onSave({
          id: `custom-${Date.now()}`,
          type: "mask",
          name: fileName,  // 使用文件名作为名称
          description: "",  // 清空描述
          mask: masks[0].trim(),
          createdAt: new Date().toISOString(),
        });
      } else {
        setMaskPath(selected);
        props.onSave({
          id: `custom-${Date.now()}`,
          type: "mask",
          name: fileName,  // 使用文件名作为名称
          description: "",  // 清空描述
          path: selected,
          createdAt: new Date().toISOString(),
        });
      }
      
      // 重置表单
      resetForm();
    } catch (err) {
      setMessage(String(err));
    }
  }

  // 添加导入规则文件功能
  async function importRuleFile() {
    const selected = await open({ multiple: false, directory: false });
    if (typeof selected !== "string") return;
    try {
      const content = await invoke<FilePreviewResponse>("preview_text_file", { path: selected, allowFull: true });
      const rules = content.content.trim().split('\n').filter(line => line.trim());
      if (rules.length === 0) {
        setMessage(isZh ? "规则文件为空" : "Rule file is empty");
        return;
      }
      
      // 提取文件名（兼容 Windows 和 Unix 路径）
      const fileName = selected.replace(/\\/g, '/').split('/').pop() || "Rules";
      
      // 清空之前的名称状态，确保使用文件名
      setName("");

      // 立即保存，使用文件名作为名称
      props.onSave({
        id: `custom-${Date.now()}`,
        type: "rule",
        name: fileName,  // 只使用文件名
        description: "",  // 清空描述，不使用模板描述
        path: selected,
        size: rules.length,
        createdAt: new Date().toISOString(),
      });
      
      // 重置表单
      resetForm();
    } catch (err) {
      setMessage(String(err));
    }
  }

  // 通用文件编辑函数（适用于字典、掩码文件、规则文件等）
  async function editFileResource(resource: CustomResource) {
    if (!resource.path) return;

    // 检查文件是否可编辑
    const editable = await invoke<boolean>("is_resource_editable", { 
        path: resource.path, 
        resource_type: resource.type 
    });
    setIsEditable(editable);
    
    if (!editable) {
        setMessage(props.text.readonlyFileWarning || "This file cannot be edited. Please import a copy to the application directory.");
        return;
    }

    try {
      const preview = await invoke<FilePreviewResponse>("preview_text_file", { path: resource.path, allowFull: true });
      setEditing(resource);
      setType(resource.type);
      setName(resource.name);
      setDescription(resource.description);
      setEditContent(preview.content);
      setEditTruncated(preview.truncated);
      setAppendContent("");
      setMessage(preview.truncated ? props.text.previewTruncated.replace("{count}", String(preview.lineCount)) : "");
    } catch (err) {
      setMessage(String(err));
    }
  }

  // 通用文件保存函数（适用于字典、掩码文件、规则文件等）
  async function saveFileResourceEdit() {
    if (!editing?.path) return;
    try {
      const content = editTruncated ? appendContent : editContent;
      
      // 如果内容不为空，保存内容
      if (content.trim()) {
        await invoke("save_custom_dictionary_content", { path: editing.path, content });
      }
      
      // 保存名称和其他信息
      props.onSave({ 
        ...editing, 
        name: name.trim() || editing.name,
        description: description.trim(),
        size: content.trim() ? (content.trim().split('\n').filter(line => line.trim()).length) : editing.size 
      });
      
      setEditing(null);
      setEditTruncated(false);
      setAppendContent("");
      setMessage("");
    } catch (err) {
      setMessage(String(err));
    }
  }

  function deleteResource(resource: CustomResource) {
    if (editing?.id === resource.id) {
      setEditing(null);
      setEditContent("");
      setEditTruncated(false);
      setAppendContent("");
    }
    props.onDelete(resource);
  }

  // 打开文件所在目录
  async function openResourceDirectory(path: string | undefined) {
      if (!path) return;  // 添加空值检查
      try {
          await invoke("open_file_directory", { filePath: path });
      } catch (err) {
          setMessage(String(err));
      }
  }

  async function dedupeDictionary(resource: CustomResource) {
    if (!resource.path) return;
    const confirmed = window.confirm(isZh
      ? "将对这个自定义字典副本去重，保留第一次出现的词条。不会修改你的原始本地字典。继续吗？"
      : "This will deduplicate this custom dictionary copy and keep the first occurrence of each entry. Your original local dictionary will not be changed. Continue?");
    if (!confirmed) return;
    setDedupingPath(resource.path);
    setMessage("");
    try {
      const result = await invoke<DictionaryDedupeResponse>("dedupe_custom_dictionary", { path: resource.path });
      props.onSave({ ...resource, size: result.size });
      setMessage(isZh
        ? `去重完成：原 ${result.originalLines} 行，保留 ${result.uniqueLines} 行，移除 ${result.removedLines} 行。`
        : `Deduplicated: ${result.originalLines} original lines, ${result.uniqueLines} kept, ${result.removedLines} removed.`);
      if (editing?.id === resource.id) {
        const preview = await invoke<FilePreviewResponse>("preview_text_file", { path: resource.path, allowFull: true });
        setEditContent(preview.content);
        setEditTruncated(preview.truncated);
        setAppendContent("");
      }
    } catch (err) {
      setMessage(String(err));
    } finally {
      setDedupingPath("");
    }
  }

  return createPortal(
    <div className="modal-backdrop" role="presentation">
      <section className="custom-manager-modal" role="dialog" aria-modal="true" aria-label={props.text.manageCustomResources}>
        <div className="panel-heading">
          <div><p className="eyebrow">Custom Library</p><h2>{props.text.manageCustomResources}</h2></div>
          <button className="icon-button" type="button" onClick={props.onClose}><X size={15} /></button>
        </div>
        {message && <div className="settings-test warn">{message}</div>}
        <div className="custom-manager-form">
          <div className="form-row">
            <div className="form-group">
              <label>{isZh ? "类型" : "Type"}</label>
              <select value={type} onChange={(event) => setType(event.currentTarget.value as CustomResource["type"])}>
                <option value="dictionary">{props.text.customDictionaryName}</option>
                <option value="mask">{props.text.customMaskName}</option>
                <option value="template">{props.text.customTemplateName}</option>
                <option value="charset">{props.text.customCharsetName}</option>
                <option value="rule">{props.text.customRuleName}</option>
              </select>
            </div>
            <div className="form-group">
              <label>{props.text.customName}</label>
              <input value={name} onChange={(event) => setName(event.currentTarget.value)} placeholder={props.text.customName} />
            </div>
            <div className="form-group">
              <label>{props.text.customDescription}</label>
              <input value={description} onChange={(event) => setDescription(event.currentTarget.value)} placeholder={props.text.customDescription} />
            </div>
          </div>
          {type === "mask" && (
            <div>
              <input value={mask} onChange={(event) => setMaskValue(event.currentTarget.value)} placeholder="?d?d?d?d" />
              <button type="button" onClick={importMaskFile}>{props.text.importMaskFile}</button>
            </div>
          )}
          {type === "template" && (
            <div className="template-inputs">
              <input 
                value={prefixMask} 
                onChange={(event) => setPrefixMask(event.currentTarget.value)} 
                placeholder={props.text.prefixMask} 
              />
              <input 
                value={suffixMask} 
                onChange={(event) => setSuffixMask(event.currentTarget.value)} 
                placeholder={props.text.suffixMask} 
              />
            </div>
          )}
          {type === "charset" && (
            <div>
              <select value={charsetSlot} onChange={(event) => setCharsetSlot(event.currentTarget.value as "1" | "2" | "3" | "4")}>
                <option value="1">?1</option>
                <option value="2">?2</option>
                <option value="3">?3</option>
                <option value="4">?4</option>
              </select>
              <input value={charsetValue} onChange={(event) => setCharsetValue(event.currentTarget.value)} placeholder="?l?d" />
            </div>
          )}
          {type === "rule" && (
            <button type="button" onClick={importRuleFile}>{props.text.importRuleFile}</button>
          )}
          {type === "dictionary" ? (
            <div>
              <button type="button" onClick={importDictionaryCopy}>{props.text.importCustomDictionary}</button>
              {editing && editing.type === "dictionary" && (
                <button type="button" onClick={() => void saveFileResourceEdit()}>{props.text.save}</button>
              )}
            </div>
          ) : (
            <button type="button" onClick={saveManualResource}>
              {editing && editing.type !== "dictionary" ? props.text.save : 
              type === "mask" ? props.text.addMaskResource : 
              type === "charset" ? props.text.addCharsetResource : 
              props.text.addTemplateResource}
            </button>
          )}
        </div>
        <div className="custom-manager-list">
          {(() => {
            // 合并自定义资源和用户字典
            const combinedResources = [
              ...props.resources.map(r => ({ ...r, source: "custom" as const })),
              ...props.userDictionaries.map(dict => ({
                id: `userdict-${dict.path}`,
                type: "dictionary" as const,
                name: dict.name,
                description: "",
                path: dict.path,
                size: dict.size,
                createdAt: new Date().toISOString(),
                source: "user" as const
              }))
            ];
            
            if (!combinedResources.length) {
              return <div className="empty-state">{props.text.noCustomResources}</div>;
            }
            
            return combinedResources.map((resource) => {
              const isUserDict = resource.source === "user";
              
              return (
                <div className="resource-row" key={resource.id}>
                  <div>
                    <div className="resource-header">
                      <span className={`resource-type-badge resource-type-${isUserDict ? "dictionary" : resource.type}`}>
                        {isUserDict ? (props.text.resourceDictionary || "Dict") : resourceTypeBadgeText(resource.type, props.text)}
                      </span>
                      <strong>{resource.name}</strong>
                    </div>
                    <span>
                      {isUserDict ? props.text.userDictionaries : customResourceTypeLabel(resource, props.text)} · 
                      {isUserDict ? `${formatSize(resource.size)} · ${shortPath(resource.path)}` : customResourceValue(resource)}
                    </span>
                    <em>
                      {isUserDict ? props.text.resourceDictionaryHelp : 
                      resource.description || (resource.type === "dictionary" ? props.text.resourceDictionaryHelp : 
                      resource.type === "charset" ? props.text.charsetHint : 
                      resource.type === "mask" ? (resource.path ? props.text.resourceMaskFileHelp : props.text.resourceMaskHelp) : 
                      resource.type === "rule" ? props.text.resourceRuleHelp : props.text.templateHint)}
                    </em>
                  </div>
                  <div className="resource-actions">
                    {isUserDict ? (
                      <>
                        <button type="button" onClick={() => {
                          // 创建一个不包含 source 属性的对象传递给 onUse
                          const { source, ...resourceWithoutSource } = resource;
                          props.onUse(resourceWithoutSource as CustomResource);
                        }}>{props.text.use}</button>
                        <button type="button" onClick={() => props.onRemoveDictionary(resource.path)}><Trash2 size={14} /></button>
                      </>
                    ) : (
                      <>
                        <button type="button" onClick={() => props.onUse(resource)}>{props.text.use}</button>
                        {resource.path ? (
                          // 有路径的资源（文件类型）：使用文件编辑函数
                          <button type="button" onClick={() => void editFileResource(resource)}>{props.text.edit}</button>
                        ) : (
                          // 无路径的资源（手动输入类型）：使用手动编辑函数
                          <button type="button" onClick={() => editManualResource(resource)}>{props.text.edit}</button>
                        )}
                        {resource.type === "dictionary" && <button type="button" onClick={() => void dedupeDictionary(resource)} disabled={dedupingPath === resource.path}>{dedupingPath === resource.path ? (isZh ? "去重中" : "Deduping") : (isZh ? "去重" : "Dedupe")}</button>}
                        <button type="button" onClick={() => void openResourceDirectory(resource.path)} disabled={!resource.path}>{props.text.directory || (isZh ? "目录" : "Directory")}</button>
                        <button type="button" onClick={() => deleteResource(resource)}>{props.text.delete}</button>
                      </>
                    )}
                  </div>
                </div>
              );
            });
          })()}
        </div>
        {(editing && editing.type === "dictionary") || (editing && editing.type === "rule") ? (
          <section className="dictionary-editor">
            <div className="line-title"><span>{props.text.edit}: {props.editing!.name}</span></div>
            
            {!isEditable && (
              <div className="readonly-warning">
                  {props.text.readonlyFileWarning || "This file is read-only. Please import a copy to edit."}
              </div>
            )}

            {editTruncated && <div className="settings-test warn">{props.text.largeDictionaryAppendOnly}</div>}
            {editTruncated && <pre className="resource-preview-output dictionary-edit-preview">{editContent || props.text.previewEmpty}</pre>}
            
            {/* 只有可编辑时才显示编辑框 */}
            {isEditable && (
                <textarea
                    value={editTruncated ? appendContent : editContent}
                    onChange={(event) => editTruncated ? setAppendContent(event.currentTarget.value) : setEditContent(event.currentTarget.value)}
                    placeholder={editTruncated ? props.text.appendDictionaryPlaceholder : undefined}
                    spellCheck={false}
                />
            )}
            
            {/* 预览模式（不可编辑时） */}
            {!isEditable && editContent && (
                <pre className="resource-preview-output">{editContent}</pre>
            )}
            <div className="settings-actions">
              <button className="ghost-button" type="button" onClick={() => { 
                  setEditing(null); 
                  setEditTruncated(false); 
                  setAppendContent(""); 
                  setMessage(""); 
                  setIsEditable(true);  // 重置状态
              }}>{props.text.cancel}</button>
              <button className="primary-button" type="button" onClick={() => void saveFileResourceEdit()}>{props.text.save}</button>
            </div>
          </section>
        ) : null}
      </section>
    </div>,
    document.body,
  );
}

// 简化版添加/编辑自定义资源组件
function AddCustomResourceDialog(props: {
  text: UiText;
  onClose: () => void;
  onSave: (resource: CustomResource) => void;
  editing?: CustomResource | null;  // 新增：编辑模式时传入要编辑的资源
}) {
  const [type, setType] = useState<CustomResource["type"]>(props.editing?.type || "dictionary");
  const [name, setName] = useState(props.editing?.name || "");
  const [description, setDescription] = useState(props.editing?.description || "");
  const [mask, setMaskValue] = useState(props.editing?.mask || "");
  const [prefixMask, setPrefixMask] = useState(props.editing?.prefixMask || "");
  const [suffixMask, setSuffixMask] = useState(props.editing?.suffixMask || "");
  const [charsetSlot, setCharsetSlot] = useState<"1" | "2" | "3" | "4">(props.editing?.charsetSlot ?? "1");
  const [charsetValue, setCharsetValue] = useState(props.editing?.charsetValue || "");
  const [rulePath, setRulePath] = useState(props.editing?.path || "");
  const [ruleLines, setRuleLines] = useState(props.editing?.size || 0);
  const [ruleType, setRuleType] = useState<"left" | "right">((props.editing?.ruleType as "left" | "right") || "left");
  const [ruleValue, setRuleValue] = useState(props.editing?.ruleValue || "");
  const [ruleEditorOpen, setRuleEditorOpen] = useState(false);
  const [ruleEditorTarget, setRuleEditorTarget] = useState<"left" | "right">("left");
  const [maskPath, setMaskPath] = useState(props.editing?.path || "");
  const [editContent, setEditContent] = useState("");  // 字典内容
  const [editTruncated, setEditTruncated] = useState(false);
  const [appendContent, setAppendContent] = useState("");
  const [message, setMessage] = useState("");
  const [dedupingPath, setDedupingPath] = useState("");
  const [copyToAppDir, setCopyToAppDir] = useState(false);
  const [importedPath, setImportedPath] = useState("");  // 暂存导入的文件路径
  const [importedSize, setImportedSize] = useState(0);    // 暂存文件大小
  const [importedName, setImportedName] = useState("");  // 暂存文件名
  const [importedType, setImportedType] = useState<"dictionary" | "mask" | "rule">("dictionary"); // 暂存导入类型
  const isZh = props.text.settingsTitle === "设置";
  const isEditing = !!props.editing;
  const [importedFiles, setImportedFiles] = useState<Array<{
    path: string;
    name: string;
    size: number;
    type: "dictionary" | "mask" | "rule";
  }>>([]);

  useEffect(() => {
    // 如果是编辑模式且是文件类型（字典或掩码文件），加载文件内容
    if (isEditing && props.editing?.path && (props.editing.type === "dictionary" || props.editing.type === "mask" || props.editing.type === "rule")) {
      loadDictionaryContent(props.editing.path);
    }
  }, [isEditing, props.editing]);

  async function loadDictionaryContent(path: string) {
    try {
      const preview = await invoke<FilePreviewResponse>("preview_text_file", { path, allowFull: true });
      setEditContent(preview.content);
      setEditTruncated(preview.truncated);
      setAppendContent("");
      setMessage(preview.truncated ? props.text.previewTruncated.replace("{count}", String(preview.lineCount)) : "");
    } catch (err) {
      setMessage(String(err));
    }
  }

  function resetForm() {
    setName("");
    setDescription("");
    setMaskValue("");
    setPrefixMask("");
    setSuffixMask("");
    setCharsetSlot("1");
    setCharsetValue("");
    setRulePath("");
    setRuleLines(0);
    setMaskPath("");
    setEditContent("");
    setEditTruncated(false);
    setAppendContent("");
    setMessage("");
    setImportedPath("");
    setImportedSize(0);
    setImportedName("");
    setImportedType("dictionary");
    setCopyToAppDir(false);
    setRuleType("left");
    setRuleValue("");
    setImportedFiles([]);
  }


  function saveManualResource() {
    if (type === "mask" && !mask.trim() && !maskPath && !isEditing) return;
    if (type === "template" && !prefixMask.trim() && !suffixMask.trim()) return;
    if (type === "charset" && !charsetValue.trim()) return;
    if (type === "rule" && !rulePath && !ruleValue.trim() && !isEditing) return;
    
    let defaultName = "";
    switch (type) {
      case "mask":
        defaultName = maskPath 
          ? maskPath.split('/').pop() || maskPath.split('\\').pop() || mask.trim()
          : mask.trim();
        break;
      case "charset":
        defaultName = `?${charsetSlot} ${charsetValue.trim()}`;
        break;
      case "rule":
        // 规则文件用文件名，左右规则用规则值
        defaultName = rulePath 
          ? rulePath.split('/').pop() || rulePath.split('\\').pop() || "Rules"
          : (ruleType === "left" ? '-j ' : '-k ') + ruleValue.trim();
        break;
      case "template":
        defaultName = `${prefixMask || "<empty>"} + word + ${suffixMask || "<empty>"}`;
        break;
    }
    
    let finalName = name.trim() || defaultName;
    if (!name.trim()) {
      if (type === "rule" && rulePath) {
        finalName = rulePath.split('/').pop() || rulePath.split('\\').pop() || "Rules";
      } else if (type === "mask" && maskPath) {
        finalName = maskPath.split('/').pop() || maskPath.split('\\').pop() || mask.trim() || "Masks";
      }
    }
    
    props.onSave({
      id: isEditing ? props.editing!.id : `custom-${Date.now()}`,
      type,
      name: finalName,
      description: description.trim(),
      mask: type === "mask" ? mask.trim() : undefined,
      prefixMask: type === "template" ? prefixMask.trim() : undefined,
      suffixMask: type === "template" ? suffixMask.trim() : undefined,
      charsetSlot: type === "charset" ? charsetSlot : undefined,
      charsetValue: type === "charset" ? charsetValue.trim() : undefined,
      path: type === "rule" && rulePath ? rulePath : (type === "mask" ? maskPath : undefined),
      size: type === "rule" && rulePath ? ruleLines : undefined,
      // 添加左右规则的保存
      ruleType: type === "rule" && ruleValue.trim() ? ruleType : undefined,
      ruleValue: type === "rule" && ruleValue.trim() ? ruleValue.trim() : undefined,
      createdAt: props.editing?.createdAt ?? new Date().toISOString(),
      sortOrder: props.editing?.sortOrder,
    });
    
    resetForm();
    props.onClose();
  }

  async function saveFileResourceEdit() {
    if (!props.editing?.path) return;
    try {
      const content = editTruncated ? appendContent : editContent;
      
      if (content.trim()) {
        await invoke("save_custom_dictionary_content", { path: props.editing.path, content });
      }
      
      props.onSave({ 
        ...props.editing, 
        name: name.trim() || props.editing.name,
        description: description.trim(),
        size: content.trim() ? (content.trim().split('\n').filter(line => line.trim()).length) : props.editing.size 
      });
      
      setEditTruncated(false);
      setAppendContent("");
      setMessage("");
      props.onClose();
    } catch (err) {
      setMessage(String(err));
    }
  }

  async function dedupeDictionary() {
    if (!props.editing?.path) return;
    const confirmed = window.confirm(isZh
      ? "将对这个自定义字典副本去重，保留第一次出现的词条。不会修改你的原始本地字典。继续吗？"
      : "This will deduplicate this custom dictionary copy and keep the first occurrence of each entry. Your original local dictionary will not be changed. Continue?");
    if (!confirmed) return;
    setDedupingPath(props.editing.path);
    setMessage("");
    try {
      const result = await invoke<DictionaryDedupeResponse>("dedupe_custom_dictionary", { path: props.editing.path });
      
      // 先设置消息，再调用 onSave
      const msg = isZh
        ? `去重完成：原 ${result.originalLines} 行，保留 ${result.uniqueLines} 行，移除 ${result.removedLines} 行。`
        : `Deduplicated: ${result.originalLines} original lines, ${result.uniqueLines} kept, ${result.removedLines} removed.`;
      setMessage(msg);
      
      // 使用 setTimeout 延迟调用 onSave，确保消息先显示
      setTimeout(() => {
        props.onSave({ ...props.editing!, size: result.size });
      }, 0);
      
      // 重新加载字典内容
      await loadDictionaryContent(props.editing.path);
      setMessage(msg);
    } catch (err) {
      setMessage(String(err));
    } finally {
      setDedupingPath("");
    }
  }

  async function importDictionaryCopy() {
    // 启用多选功能
    const selected = await open({ multiple: true, directory: false });
    // 处理用户未选择或选择空的情况
    if (!selected || (Array.isArray(selected) && selected.length === 0)) return;
    
    // 统一处理单文件和多文件情况
    const files = Array.isArray(selected) ? selected : [selected];
    
    try {
      // 收集所有文件信息
      const fileList: Array<{path: string; name: string; size: number; type: "dictionary"}> = [];
      
      for (const filePath of files) {
        const fileName = filePath.replace(/\\/g, '/').split('/').pop() || "dictionary.txt";
        const preview = await invoke<FilePreviewResponse>("preview_text_file", { path: filePath, allowFull: false });
        
        fileList.push({
          path: filePath,
          name: fileName,
          size: preview.fileSize,
          type: "dictionary"
        });
      }
      
      // 暂存所有文件信息
      setImportedFiles(fileList);
      
      // 显示已选择的文件路径（支持中英切换）
      if (fileList.length === 1) {
        // 单个文件时显示完整路径
        setMessage(isZh ? `已选择文件：${fileList[0].path}` : `Selected file: ${fileList[0].path}`);
      } else {
        // 多个文件时显示文件名列表
        const fileNames = fileList.map(f => f.name).join(', ');
        setMessage(isZh ? `已选择 ${fileList.length} 个文件：${fileNames}` : `Selected ${fileList.length} files: ${fileNames}`);
      }
      
      // 同时设置单个文件的暂存信息（保持兼容性）
      if (fileList.length === 1) {
        setImportedPath(fileList[0].path);
        setImportedName(fileList[0].name);
        setImportedSize(fileList[0].size);
      }
      setImportedType("dictionary");
    } catch (err) {
      setMessage(String(err));
    }
  }


  async function saveImportedResource() {
    // 如果有多个文件待保存，优先处理多文件情况
    if (importedFiles.length > 0) {
      try {
        const now = new Date().toISOString();
        
        for (let i = 0; i < importedFiles.length; i++) {
          const importedFile = importedFiles[i];
          let finalPath = importedFile.path;
          let finalSize = importedFile.size;
          let finalName = importedFile.name;
          
          if (copyToAppDir) {
            const imported = await invoke<UserDictionary>("import_custom_dictionary", { 
              source: importedFile.path, 
              copyToAppDir: true 
            });
            finalPath = imported.path;
            finalSize = imported.size;
          }
          
          // 单个文件时优先使用用户输入的名称，多个文件时使用文件名
          const resourceName = importedFiles.length === 1 ? (name.trim() || finalName) : finalName;
          
          // 使用索引确保每个资源有唯一的 ID
          props.onSave({
            id: `custom-${Date.now()}-${i}`,
            type: importedFile.type,
            name: resourceName,
            description: description.trim(),
            path: finalPath,
            size: finalSize,
            createdAt: now,
            isBuiltinCopy: copyToAppDir,
          });
        }
        
        resetForm();
        setImportedFiles([]);  // 清空暂存的文件列表
        
        props.onClose();
        return;  // 多文件保存完成，直接返回
      } catch (err) {
        setMessage(String(err));
        return;
      }
    }
    
    // 原有单文件保存逻辑
    if (!importedPath && !(type === "mask" && mask.trim()) && !(type === "rule" && ruleValue.trim())) return;
    try {
      let finalPath = importedPath;
      let finalSize = importedSize;
      
      if (copyToAppDir) {
        const imported = await invoke<UserDictionary>("import_custom_resource", { 
          source: importedPath, 
          resourceType: importedType,
          copyToAppDir: true 
        });
        finalPath = imported.path;
        finalSize = imported.size;
      }
      
      const now = new Date().toISOString();
      
      if (type === "dictionary") {
        props.onSave({
          id: `custom-${Date.now()}`,
          type: "dictionary",
          name: name.trim() || importedName,
          description: description.trim(),
          path: finalPath,
          size: finalSize,
          createdAt: now,
          isBuiltinCopy: copyToAppDir,
        });
      } else if (type === "mask") {
        // 如果有导入文件，保存文件路径；否则保存手动输入的掩码
        if (importedPath) {
          props.onSave({
            id: `custom-${Date.now()}`,
            type: "mask",
            name: name.trim() || importedName,
            description: description.trim(),
            path: finalPath,
            size: finalSize,
            createdAt: now,
            isBuiltinCopy: copyToAppDir,
          });
        } else {
          // 手动输入的掩码
          props.onSave({
            id: `custom-${Date.now()}`,
            type: "mask",
            name: name.trim() || mask.trim() || "Mask",
            description: description.trim(),
            mask: mask.trim(),
            createdAt: now,
          });
        }
      } else if (type === "rule") {
        // 如果有导入文件，保存文件路径；否则保存手动输入的规则
        if (importedPath) {
          props.onSave({
            id: `custom-${Date.now()}`,
            type: "rule",
            name: name.trim() || importedName,
            description: description.trim(),
            path: finalPath,
            size: importedSize,
            createdAt: now,
            isBuiltinCopy: copyToAppDir,
          });
        } else {
          // 手动输入的规则
          props.onSave({
            id: `custom-${Date.now()}`,
            type: "rule",
            name: name.trim() || (ruleType === "left" ? '-j ' : '-k ') + ruleValue.trim(),
            description: description.trim(),
            ruleType: ruleType,
            ruleValue: ruleValue.trim(),
            createdAt: now,
          });
        }
      }
      
      resetForm();
      props.onClose();
    } catch (err) {
      setMessage(String(err));
    }
  }

  async function importMaskFile() {
    // 启用多选功能
    const selected = await open({ multiple: true, directory: false });
    // 处理用户未选择或选择空的情况
    if (!selected || (Array.isArray(selected) && selected.length === 0)) return;
    
    // 统一处理单文件和多文件情况
    const files = Array.isArray(selected) ? selected : [selected];
    
    try {
      // 收集所有文件信息
      const fileList: Array<{path: string; name: string; size: number; type: "mask"}> = [];
      
      for (const filePath of files) {
        const content = await invoke<FilePreviewResponse>("preview_text_file", { path: filePath, allowFull: true });
        const masks = content.content.trim().split('\n').filter(line => line.trim());
        
        if (masks.length === 0) {
          continue;  // 跳过空文件
        }
        
        const fileName = filePath.replace(/\\/g, '/').split('/').pop() || "Masks";
        
        fileList.push({
          path: filePath,
          name: fileName,
          size: content.fileSize,
          type: "mask"
        });
      }
      
      // 如果所有文件都是空的，显示提示
      if (fileList.length === 0) {
        setMessage(isZh ? "所有选中的文件都是空的" : "All selected files are empty");
        return;
      }
      
      // 暂存所有文件信息
      setImportedFiles(fileList);
      
      // 显示已选择的文件路径（支持中英切换）
      if (fileList.length === 1) {
        // 单个文件时显示完整路径
        setMessage(isZh ? `已选择文件：${fileList[0].path}` : `Selected file: ${fileList[0].path}`);
      } else {
        // 多个文件时显示文件名列表
        const fileNames = fileList.map(f => f.name).join(', ');
        setMessage(isZh ? `已选择 ${fileList.length} 个文件：${fileNames}` : `Selected ${fileList.length} files: ${fileNames}`);
      }
      
      // 同时设置单个文件的暂存信息（保持兼容性）
      if (fileList.length === 1) {
        setImportedPath(fileList[0].path);
        setImportedName(fileList[0].name);
        setImportedSize(fileList[0].size);
      }
      setImportedType("mask");
    } catch (err) {
      setMessage(String(err));
    }
  }

  async function importRuleFile() {
    // 启用多选功能
    const selected = await open({ multiple: true, directory: false });
    // 处理用户未选择或选择空的情况
    if (!selected || (Array.isArray(selected) && selected.length === 0)) return;
    
    // 统一处理单文件和多文件情况
    const files = Array.isArray(selected) ? selected : [selected];
   
    try {
      // 收集所有文件信息
      const fileList: Array<{path: string; name: string; size: number; type: "rule"}> = [];
      
      for (const filePath of files) {
        const content = await invoke<FilePreviewResponse>("preview_text_file", { path: filePath, allowFull: true });
        const rules = content.content.trim().split('\n').filter(line => line.trim());
        
        if (rules.length === 0) {
          continue;  // 跳过空文件
        }
        
        const fileName = filePath.replace(/\\/g, '/').split('/').pop() || "Rules";
        
        fileList.push({
          path: filePath,
          name: fileName,
          size: content.fileSize,
          type: "rule"
        });
      }
      
      // 如果所有文件都是空的，显示提示
      if (fileList.length === 0) {
        setMessage(isZh ? "所有选中的文件都是空的" : "All selected files are empty");
        return;
      }
      
      // 暂存所有文件信息
      setImportedFiles(fileList);
      
      // 显示已选择的文件路径（支持中英切换）
      if (fileList.length === 1) {
        // 单个文件时显示完整路径
        setMessage(isZh ? `已选择文件：${fileList[0].path}` : `Selected file: ${fileList[0].path}`);
      } else {
        // 多个文件时显示文件名列表
        const fileNames = fileList.map(f => f.name).join(', ');
        setMessage(isZh ? `已选择 ${fileList.length} 个文件：${fileNames}` : `Selected ${fileList.length} files: ${fileNames}`);
      }
      
      // 同时设置单个文件的暂存信息（保持兼容性）
      if (fileList.length === 1) {
        setImportedPath(fileList[0].path);
        setImportedName(fileList[0].name);
        setImportedSize(fileList[0].size);
      }
      setImportedType("rule");
    } catch (err) {
      setMessage(String(err));
    }
  }

  return (
    <div className="add-resource-dialog">
      <div className="panel-heading">
        <div><p className="eyebrow">{isEditing ? "Edit Resource" : "Add Resource"}</p><h2>{isEditing ? props.text.editCustomResource : props.text.addCustomResource}</h2></div>
        <button className="icon-button" type="button" onClick={props.onClose}><X size={15} /></button>
      </div>
      {message && <div className="settings-test warn">{message}</div>}
      <div className="custom-manager-form">
        <div className="form-row">
          <div className="form-group">
            <label>{isZh ? "类型" : "Type"}</label>
            <select 
              value={type} 
              onChange={(event) => setType(event.currentTarget.value as CustomResource["type"])}
              disabled={isEditing}  // 编辑模式下类型不可改
            >
              <option value="dictionary">{props.text.customDictionaryName}</option>
              <option value="mask">{props.text.customMaskName}</option>
              <option value="template">{props.text.customTemplateName}</option>
              <option value="charset">{props.text.customCharsetName}</option>
              <option value="rule">{props.text.customRuleName}</option>
            </select>
          </div>
          <div className="form-group">
            <label>{props.text.customName}</label>
            <input value={name} onChange={(event) => setName(event.currentTarget.value)} placeholder={props.text.customName} />
          </div>
          <div className="form-group">
            <label>{props.text.customDescription}</label>
            <input value={description} onChange={(event) => setDescription(event.currentTarget.value)} placeholder={props.text.customDescription} />
          </div>
        </div>
        
        {/* 字典内容编辑（仅编辑模式且是字典类型） */}
        {(isEditing && type === "dictionary" && props.editing?.path) || (isEditing && type === "rule" && props.editing?.path) ? (
          <div className="dictionary-editor">
            <label>{props.text.content}</label>
            {editTruncated ? (
              <>
                <pre className="dictionary-preview">{editContent}</pre>
                <p className="truncated-hint">{props.text.largeDictionaryAppendOnly}</p>
                <textarea 
                  value={appendContent} 
                  onChange={(event) => setAppendContent(event.currentTarget.value)} 
                  placeholder={props.text.appendDictionaryLines}
                  className="append-textarea"
                />
              </>
            ) : (
              <textarea 
                value={editContent} 
                onChange={(event) => setEditContent(event.currentTarget.value)} 
                className="dictionary-textarea"
              />
            )}
          </div>
        ) : null}
        
        {type === "mask" && (
          <div>
            {/* 编辑模式：区分字符串掩码和掩码文件 */}
            {isEditing && props.editing?.path ? (
              // 掩码文件：显示预览编辑框（与字典类似）
              <>
                {editTruncated && <div className="settings-test warn">{props.text.largeDictionaryAppendOnly}</div>}
                {editTruncated && <pre className="resource-preview-output dictionary-edit-preview">{editContent || props.text.previewEmpty}</pre>}
                <textarea
                  value={editTruncated ? appendContent : editContent}
                  onChange={(event) => editTruncated ? setAppendContent(event.currentTarget.value) : setEditContent(event.currentTarget.value)}
                  placeholder={editTruncated ? props.text.appendDictionaryPlaceholder : undefined}
                  className="dictionary-textarea"
                />
              </>
            ) : (
              // 字符串掩码：显示输入框
              <input value={mask} onChange={(event) => setMaskValue(event.currentTarget.value)} placeholder="?d?d?d?d" />
            )}
            <div className="mask-checkbox-container">
              {!isEditing && (
                <>
                  <label className="checkbox-label">
                    <input type="checkbox" checked={copyToAppDir} onChange={(e) => setCopyToAppDir(e.target.checked)} />
                    <span>{isZh ? "复制文件到软件数据目录" : "Copy file to app data directory"}</span>
                  </label>
                  <button type="button" onClick={importMaskFile}>{props.text.importMaskFile}</button>
                </>
              )}
              <button type="button" onClick={isEditing && props.editing?.path ? saveFileResourceEdit : (isEditing ? saveManualResource : saveImportedResource)}>
                {isEditing ? props.text.save : (importedPath ? props.text.save : props.text.addMaskResource)}
              </button>
            </div>
          </div>
        )}
        {type === "template" && (
          <div className="template-inputs">
            <input 
              value={prefixMask} 
              onChange={(event) => setPrefixMask(event.currentTarget.value)} 
              placeholder={props.text.prefixMask} 
            />
            <input 
              value={suffixMask} 
              onChange={(event) => setSuffixMask(event.currentTarget.value)} 
              placeholder={props.text.suffixMask} 
            />
          </div>
        )}
        {type === "charset" && (
          <div className="charset-row">
            <select className="charset-slot" value={charsetSlot} onChange={(event) => setCharsetSlot(event.currentTarget.value as "1" | "2" | "3" | "4")}>
              <option value="1">?1</option>
              <option value="2">?2</option>
              <option value="3">?3</option>
              <option value="4">?4</option>
            </select>
            <input className="charset-value" value={charsetValue} onChange={(event) => setCharsetValue(event.currentTarget.value)} placeholder="?l?d" />
          </div>
        )}
        
        {/* 操作按钮区域 */}
        <div className="form-actions">
          {/* 字典去重按钮（仅编辑模式且是字典类型） */}
          {isEditing && type === "dictionary" && props.editing?.path && (
            <button 
              type="button" 
              className="dedupe-button"
              onClick={dedupeDictionary}
              disabled={!!dedupingPath}
            >
              {dedupingPath ? (props.text.processing || "Processing...") : props.text.dedupeDictionary}
            </button>
          )}
          
          {/* 保存按钮 */}
          {(type === "dictionary" || type === "rule") ? (
            <>
              {type === "rule" && (!isEditing || (isEditing && props.editing?.ruleValue)) && (
                <div className="charset-row rule-edit-row">
                  <select className="charset-slot" value={ruleType} onChange={(event) => setRuleType(event.currentTarget.value as "left" | "right")}>
                    <option value="left">{props.text.leftRule}</option>
                    <option value="right">{props.text.rightRule}</option>
                  </select>
                  <input className="charset-value" value={ruleValue} onChange={(event) => setRuleValue(event.currentTarget.value)} placeholder={props.text.rulePlaceholder} />
                  <button 
                    type="button" 
                    className="rule-editor-btn"
                    onClick={() => { 
                      setRuleEditorTarget(ruleType);  // 用当前选中的 ruleType 作为初始目标
                      setRuleEditorOpen(true); 
                    }}
                  >
                    {props.text.ruleEditor}
                  </button>
                </div>
              )}
              
              {!isEditing && (
                // 复制文件到软件目录勾选框
                <label className="checkbox-label">
                  <input type="checkbox" checked={copyToAppDir} onChange={(e) => setCopyToAppDir(e.target.checked)} />
                  <span>{isZh ? "复制文件到软件数据目录" : "Copy file to app data directory"}</span>
                </label>
              )}
              {!isEditing ? (
                <>
                  {/* 字典：导入按钮 + 保存按钮 */}
                  {type === "dictionary" && (
                    <button type="button" onClick={importDictionaryCopy}>{props.text.importCustomDictionary}</button>
                  )}
                  
                  {/* 规则：导入按钮 + 新增规则按钮（不再需要导入后显示保存按钮） */}
                  {type === "rule" && (
                    <>
                      <button type="button" onClick={importRuleFile}>{props.text.importRuleFile}</button>
                      <button type="button" onClick={saveImportedResource}>{props.text.addRuleResource}</button>
                    </>
                  )}
                  
                  {/* 字典的保存按钮（导入后显示） */}
                  {type === "dictionary" && (importedPath || importedFiles.length > 0) && (
                    <button type="button" onClick={saveImportedResource}>{props.text.save}</button>
                  )}
                </>
              ) : (
                // 左右规则（有 ruleValue）用 saveManualResource，规则文件用 saveFileResourceEdit
                type === "rule" && props.editing?.ruleValue ? (
                  <button type="button" onClick={saveManualResource}>{props.text.save}</button>
                ) : (
                  <button type="button" onClick={() => void saveFileResourceEdit()}>{props.text.save}</button>
                )
              )}
            </>
          ) : (type === "template" || type === "charset") ? (
            // charset 和 template 的保存按钮（保持不变）
            <button type="button" onClick={saveManualResource}>
              {isEditing ? props.text.save : 
              type === "charset" ? props.text.addCharsetResource : 
              props.text.addTemplateResource}
            </button>
          ) : null}
        </div>
      </div>
      {/* 规则编辑器弹窗 */}
      {ruleEditorOpen && (
        <RuleEditorModal
          isOpen={ruleEditorOpen}
          onClose={() => setRuleEditorOpen(false)}
          text={props.text}
          initialTarget={ruleEditorTarget}
          onApply={(rule, target) => {
            setRuleType(target);        // 同步 ruleType（左/右）
            setRuleValue(prev => (prev || "") + rule);  // 追加规则
            setRuleEditorOpen(false);
          }}
        />
      )}
    </div>
  );
}

function AddPresetDialog(props: {
  text: UiText;
  onClose: () => void;
  onSave: (preset: PresetConfig) => void;
  editing?: PresetConfig | null;
  resources: ResourceInfo[];
  userDictionaries: UserDictionary[];
  customResources: CustomResource[];
  showToast?: (message: string) => void;
  ruleEditorTarget: "left" | "right";
  openRuleEditor: (target: "left" | "right") => void;
  onRuleEditorApply: (rule: string, target: "left" | "right") => void;
}) {
  const isZh = props.text.settingsTitle === "设置";
  const isEditing = !!props.editing;

  const [ruleEditorOpen, setRuleEditorOpen] = useState(false);
  const [ruleEditorTarget, setRuleEditorTarget] = useState<"left" | "right">("left");
  
  // 状态定义
  const [attackModeDropdownOpen, setAttackModeDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const [attackMode, setAttackMode] = useState<AttackMode>(props.editing?.attackMode || 0);
  const [name, setName] = useState(props.editing?.name || "");
  const [description, setDescription] = useState(props.editing?.description || "");
  const hashMode = props.editing?.hashMode || "";
  const [dictionaryPaths, setDictionaryPaths] = useState<string[]>(props.editing?.dictionaryPaths || []);
  const [dictionaryPath, setDictionaryPath] = useState(props.editing?.dictionaryPath || "");
  const [dictionaryPath2, setDictionaryPath2] = useState(props.editing?.dictionaryPath2 || "");
  const [mask, setMask] = useState(props.editing?.mask || "");
  const [prefixMask, setPrefixMask] = useState(props.editing?.prefixMask || "");
  const [suffixMask, setSuffixMask] = useState(props.editing?.suffixMask || "");
  const [useLeftRule, setUseLeftRule] = useState(props.editing?.useLeftRule || false);
  const [leftRule, setLeftRule] = useState(props.editing?.leftRule || "");
  const [useRightRule, setUseRightRule] = useState(props.editing?.useRightRule || false);
  const [rightRule, setRightRule] = useState(props.editing?.rightRule || "");
  const [customCharsets, setCustomCharsets] = useState<Record<string, string>>(props.editing?.customCharsets || {});
  const [increment, setIncrement] = useState(props.editing?.increment || false);
  const [incrementMin, setIncrementMin] = useState(props.editing?.incrementMin || "");
  const [incrementMax, setIncrementMax] = useState(props.editing?.incrementMax || "");
  const [useRules, setUseRules] = useState(props.editing?.useRules || false);
  const [charsetEnabled, setCharsetEnabled] = useState(!!(props.editing?.customCharsets && Object.keys(props.editing.customCharsets).length));
  const [maskHelp, setMaskHelp] = useState(false);
  const [rulePaths, setRulePaths] = useState<string[]>(props.editing?.rulePaths || []);
  const [rulePath, setRulePath] = useState("");
  const [maskPath, setMaskPath] = useState(props.editing?.maskPath || "");
  const [createPresetPerDictionary, setCreatePresetPerDictionary] = useState(false);
  const [resourcePickerOpen, setResourcePickerOpen] = useState(false);
  const [selectedResourceKind, setSelectedResourceKind] = useState<"dictionary" | "rule" | "mask" | "charset" | "template">("dictionary");
  const [selectedResourceTarget, setSelectedResourceTarget] = useState<"primary" | "secondary">("primary");
  const [selectedRuleType, setSelectedRuleType] = useState<"left" | "right">();

  // 打开资源选择器
  const openResourcePicker = (kind: "dictionary" | "rule" | "mask" | "charset" | "template", target: "primary" | "secondary" = "primary", ruleType?: "left" | "right") => {
    setSelectedResourceKind(kind);
    setSelectedResourceTarget(target);
    setSelectedRuleType(ruleType);
    setResourcePickerOpen(true);
  };

  // 使用资源处理函数
  const useResource = (resource: ResourceInfo) => {
    if (resource.kind === "dictionary") {
      // 字典模式（0）或字典+掩码（6）或掩码+字典（7）下选择字典时追加到 dictionaryPaths
      if ((attackMode === 0 || attackMode === 6 || attackMode === 7) && selectedResourceTarget === "primary") {
        // 模式6/7下每次选择替换字典，模式0下追加字典
        if (attackMode === 6 || attackMode === 7) {
          setDictionaryPath(resource.path); 
          setDictionaryPaths([]);
        } else {
          setDictionaryPaths(prev => {
            if (prev.includes(resource.path)) return prev;
            return [...prev, resource.path];
          });
        }
      } else if (selectedResourceTarget === "primary") {
        // 其他模式下直接替换
        setDictionaryPath(resource.path);
      } else {
        setDictionaryPath2(resource.path);
      }
    }
    if (resource.kind === "rule") {
      if (selectedResourceTarget === "primary") {
        setUseRules(true);  // 启用规则开关
        setRulePaths((current) => current.includes(resource.path) ? current : [...current, resource.path]);
      }
    }
    if (resource.kind === "mask") {
      setAttackMode(3);
      setMaskPath(resource.path);
    }
  };

  // 使用自定义资源
  const useCustomResource = async (resource: CustomResource) => {
    // 检查资源引用的文件是否存在
    if (resource.path) {
      const exists = await invoke('check_file_exists', { path: resource.path });
      if (!exists) {
        const errorMsg = isZh
          ? `资源引用的文件不存在：${resource.path}`
          : `Resource file does not exist: ${resource.path}`;
        props.showToast?.(errorMsg);
        return;
      }
    }

    if (resource.type === "mask") {
      if (attackMode === 0) setAttackMode(3);
      if (resource.path) {
        setMaskPath(resource.path);
        setMask("");
      } else {
        setMask(resource.mask || "");
        setMaskPath("");
      }
    } else if (resource.type === "template") {
      setAttackMode(9);
      setPrefixMask(resource.prefixMask ?? "");
      setSuffixMask(resource.suffixMask ?? "");
    } else if (resource.type === "charset") {
      setCharsetEnabled(true);
      if (attackMode === 0) setAttackMode(3);
      // 使用 charsetSlot 和 charsetValue 构建 customCharsets
      if (resource.charsetSlot && resource.charsetValue) {
        const slot = resource.charsetSlot as string;
        const newValue = resource.charsetValue;
        setCustomCharsets((current) => {
          const result: Record<string, string> = { ...current };
          result[slot] = newValue;
          return result;
        });
      }
    } else if (resource.type === "dictionary" && resource.path) {
      const dictPath = resource.path;
      // 根据目标设置不同的字典路径
      if ((attackMode === 0 || attackMode === 6 || attackMode === 7) && selectedResourceTarget === "primary") {
        // 模式6/7下每次选择替换字典，模式0下追加字典
        if (attackMode === 6 || attackMode === 7) {
          setDictionaryPath(resource.path); 
          setDictionaryPaths([]);
        } else {
          setDictionaryPaths(prev => {
            if (prev.includes(dictPath)) return prev;
            return [...prev, dictPath];
          });
        }
      } else if (selectedResourceTarget === "primary") {
        setDictionaryPath(dictPath);
      } else {
        setDictionaryPath2(dictPath);
      }
    } else if (resource.type === "rule") {
      if (selectedRuleType === "left") {
        // 处理左侧规则表达式
        setUseRules(true);
        setUseLeftRule(true);
        setLeftRule(resource.ruleValue || "");
      } else if (selectedRuleType === "right") {
        // 处理右侧规则表达式
        setUseRules(true);
        setUseRightRule(true);
        setRightRule(resource.ruleValue || "");
      } else if (resource.path) {
        // 处理规则文件路径（当 selectedRuleType 未定义时）
        setUseRules(true);
        const rulePath: string = resource.path;
        setRulePaths((current) => current.includes(rulePath) ? current : [...current, rulePath]);
      }
    }
  };

  // 使用用户字典
  const useUserDictionary = (dict: UserDictionary) => {
    const dictPath = dict.path;
    if (dictPath) {
      // 根据目标设置不同的字典路径
      if ((attackMode === 0 || attackMode === 6 || attackMode === 7) && selectedResourceTarget === "primary") {
        // 模式6/7下每次选择替换字典，模式0下追加字典
        if (attackMode === 6 || attackMode === 7) {
          setDictionaryPath(dictPath); 
          setDictionaryPaths([]);
        } else {
          setDictionaryPaths(prev => {
            if (prev.includes(dictPath)) return prev;
            return [...prev, dictPath];
          });
        }
      } else if (selectedResourceTarget === "primary") {
        setDictionaryPath(dictPath);
      } else {
        setDictionaryPath2(dictPath);
      }
    }
  };

  useEffect(() => {
    if (maskPath) {
      setCharsetEnabled(false);
    }
  }, [maskPath]);

  // 错误/警告消息
  const [warnMessage, setWarnMessage] = useState("");

  // 生成默认名称
  function generateDefaultName(): string {
    // 从路径提取文件名（去掉路径）
    const getFileName = (path: string): string => {
      if (!path) return "";
      const name = path.split(/[\\/]/).pop() || path;
      return name; 
    };

    // 获取掩码显示
    const getMaskDisplay = (): string => {
      if (maskPath) return getFileName(maskPath);
      if (mask) return mask;
      return "";
    };

    // 获取字典名显示
    const getDictName = (path: string): string => {
      const name = getFileName(path);
      return name || (isZh ? "字典" : "Dict");
    };

    switch (attackMode) {
      case 0: { // 字典攻击
        // 模式0：字典1, 字典2 ...
        const dictNames = dictionaryPaths.length > 0 
          ? dictionaryPaths.map(p => getDictName(p)).join(", ")
          : getDictName(dictionaryPath);
        return dictNames || (isZh ? "字典攻击" : "Dictionary Attack");
      }
      case 1: { // 字典组合攻击
        // 模式1：字典1 + 字典2
        const dict1 = getDictName(dictionaryPath);
        const dict2 = getDictName(dictionaryPath2);
        const result = [dict1, dict2].filter(Boolean).join(isZh ? " + " : " + ");
        return result || (isZh ? "字典组合攻击" : "Dictionary Combo Attack");
      }
      case 3: { // 掩码攻击
        // 模式3：掩码或掩码文件名
        const maskDisplay = getMaskDisplay();
        return maskDisplay || (isZh ? "掩码攻击" : "Mask Attack");
      }
      case 6: { // 字典+掩码攻击
        // 模式6：字典名 + 掩码
        const dictName = getDictName(dictionaryPath);
        const maskDisplay = getMaskDisplay();
        const parts: string[] = [];
        if (dictName) parts.push(dictName);
        if (maskDisplay) parts.push(maskDisplay);
        return parts.join(isZh ? " + " : " + ") || (isZh ? "字典+掩码攻击" : "Hybrid Dict+Mask Attack");
      }
      case 7: { // 掩码+字典攻击
        // 模式7：掩码 + 字典名
        const dictName = getDictName(dictionaryPath);
        const maskDisplay = getMaskDisplay();
        const parts: string[] = [];
        if (maskDisplay) parts.push(maskDisplay);
        if (dictName) parts.push(dictName);
        return parts.join(isZh ? " + " : " + ") || (isZh ? "掩码+字典攻击" : "Hybrid Mask+Dict Attack");
      }
      case 9: { // 候选模板攻击
        // 模式9：前缀掩码 + 字典名 + 后缀掩码
        const parts: string[] = [];
        if (prefixMask) parts.push(prefixMask);
        const dictName = getDictName(dictionaryPath);
        if (dictName) parts.push(dictName);
        if (suffixMask) parts.push(suffixMask);
        return parts.join(isZh ? " + " : " + ") || (isZh ? "候选模板攻击" : "Template Attack");
      }
      default: 
        return isZh ? "攻击预设" : "Attack Preset";
    }
  }

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as HTMLElement;
      // 检查点击是否在下拉框外部
      if (dropdownRef.current && !dropdownRef.current.contains(target)) {
        setAttackModeDropdownOpen(false);
      }
    };
    
    // 添加全局监听
    document.addEventListener('mousedown', handleClickOutside);
    
    // 清理函数
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  // 处理保存
  function handleSave() {
    setWarnMessage("");
    
    // 自定义预设验证：模式6/7支持多字典（dictionaryPaths）
    let validationError = "";
    if (attackMode === 6 || attackMode === 7) {
      // 模式6/7：需要字典（支持多字典）和掩码
      const hasDictionary = (dictionaryPath?.trim().length || 0) > 0 || dictionaryPaths.length > 0;
      const hasMask = (mask?.trim().length || 0) > 0 || (maskPath?.trim().length || 0) > 0;
      if (!hasDictionary) {
        validationError = props.text.missingDictionary;
      } else if (!hasMask) {
        validationError = props.text.missingMask;
      }
    } else {
      const validation = validateAttackConfig({
        attackMode,
        hashMode,
        dictionaryPath,
        dictionaryPath2,
        dictionaryPaths,
        mask,
        maskFile: maskPath,
        templatePrefixMask: prefixMask,
        templateSuffixMask: suffixMask,
        requireHash: false,
      }, props.text);
      validationError = validation.valid ? "" : (validation.error || "");
    }

    if (validationError) {
      setWarnMessage(validationError);
      return;
    }

    // 从路径提取文件名（去掉路径和后缀）
    const getDictNameWithoutExt = (path: string): string => {
      const fullName = path.split(/[\\/]/).pop() || path;
      const lastDot = fullName.lastIndexOf('.');
      return lastDot !== -1 ? fullName.substring(0, lastDot) : fullName;
    };

    // 批量模式：每个字典生成一个预设
    // 字典模式(0)需要勾选，字典+掩码(6)和掩码+字典(7)模式下有多个字典时自动批量生成
    const shouldCreateMultiplePresets = 
      (createPresetPerDictionary && attackMode === 0) ||  // 字典模式需要勾选
      ((attackMode === 6 || attackMode === 7) && dictionaryPaths.length > 1);  // 模式6/7有多个字典时自动批量生成

    if (shouldCreateMultiplePresets && dictionaryPaths.length > 0) {
      dictionaryPaths.forEach((dictPath, index) => {
        const preset: PresetConfig = {
          id: isEditing ? props.editing!.id : `preset-${Date.now()}-${index}`,
          name: getDictNameWithoutExt(dictPath),
          description: description.trim(),
          attackMode,
          hashMode: hashMode || undefined,
          dictionaryPaths: undefined,
          dictionaryPath: dictPath,
          dictionaryPath2: dictionaryPath2 || undefined,
          mask: mask || undefined,
          maskPath: maskPath || undefined,
          prefixMask: prefixMask || undefined,
          suffixMask: suffixMask || undefined,
          useRules,
          useLeftRule,
          leftRule: leftRule || undefined,
          useRightRule,
          rightRule: rightRule || undefined,
          customCharsets: charsetEnabled && Object.keys(customCharsets).length ? customCharsets : undefined,
          increment,
          incrementMin: incrementMin || undefined,
          incrementMax: incrementMax || undefined,
          rulePaths: rulePaths.length ? rulePaths : undefined,
          candidates: undefined,
          isEstimated: undefined,
          createdAt: props.editing?.createdAt ?? new Date().toISOString(),
        };
        props.onSave(preset);
      });
    } else {
      // 正常模式：生成一个预设
      const preset: PresetConfig = {
        id: isEditing ? props.editing!.id : `preset-${Date.now()}`,
        name: name.trim() || generateDefaultName(),
        description: description.trim(),
        attackMode,
        hashMode: hashMode || undefined,
        dictionaryPaths: dictionaryPaths.length ? dictionaryPaths : undefined,
        dictionaryPath: dictionaryPath || (dictionaryPaths.length === 1 ? dictionaryPaths[0] : undefined),
        dictionaryPath2: dictionaryPath2 || undefined,
        mask: mask || undefined,
        maskPath: maskPath || undefined,
        prefixMask: prefixMask || undefined,
        suffixMask: suffixMask || undefined,
        useRules,
        useLeftRule,
        leftRule: leftRule || undefined,
        useRightRule,
        rightRule: rightRule || undefined,
        customCharsets: charsetEnabled && Object.keys(customCharsets).length ? customCharsets : undefined,
        increment,
        incrementMin: incrementMin || undefined,
        incrementMax: incrementMax || undefined,
        rulePaths: rulePaths.length ? rulePaths : undefined,
        candidates: undefined,
        isEstimated: undefined,
        createdAt: props.editing?.createdAt ?? new Date().toISOString(),
      };
      props.onSave(preset);
    }
    
    props.onClose();
  }

  const chooseDictionary = async () => {
    const result = await open({
      multiple: attackMode === 0 || attackMode === 6 || attackMode === 7,  // 字典模式、字典+掩码、掩码+字典模式支持多选
      filters: [
        { name: isZh ? '所有文件' : 'All Files', extensions: ['*'] }
      ],
      title: isZh ? '选择字典文件' : 'Select Dictionary File'
    });
    
    if (result) {
      if (Array.isArray(result)) {
        // 数组：模式6/7下有多个字典时替换，模式0下追加
        if (attackMode === 6 || attackMode === 7) {
          if (result.length > 1) {
            setDictionaryPaths(result);  // 多个字典：使用 dictionaryPaths
          } else if (result.length === 1) {
            setDictionaryPath(result[0]);  // 只有1个字典：使用 dictionaryPath
            setDictionaryPaths([]);  // 清空 dictionaryPaths
          }
        } else {
          setDictionaryPaths(prev => [...prev, ...result]);
        }
      } else {
        if (attackMode === 0) {
          setDictionaryPaths(prev => [...prev, result]);
        } else if (attackMode === 6 || attackMode === 7) {
          setDictionaryPaths([result]);
        } else {
          setDictionaryPath(result);
        }
      }
    }
  };

  const chooseDictionary2 = async () => {
    const result = await open({
      multiple: false,
      filters: [
        { name: isZh ? '所有文件' : 'All Files', extensions: ['*'] }
      ],
      title: isZh ? '选择第二个字典文件' : 'Select Second Dictionary File'
    });
    
    if (result) {
      setDictionaryPath2(result as string);
    }
  };

  const clearDictionary = () => {
    // 字典模式、字典+掩码、掩码+字典模式下清空 dictionaryPaths
    if (attackMode === 0 || attackMode === 6 || attackMode === 7) {
      setDictionaryPaths([]);
    }
    setDictionaryPath("");
  };
  const clearDictionary2 = () => setDictionaryPath2("");
  const removeDictionaryFromList = (path: string) => 
    setDictionaryPaths(prev => prev.filter(p => p !== path));
  const moveDictionaryUp = (index: number) => {
    const newPaths = [...dictionaryPaths];
    if (index > 0) [newPaths[index - 1], newPaths[index]] = [newPaths[index], newPaths[index - 1]];
    setDictionaryPaths(newPaths);
  };
  const moveDictionaryDown = (index: number) => {
    const newPaths = [...dictionaryPaths];
    if (index < newPaths.length - 1) [newPaths[index], newPaths[index + 1]] = [newPaths[index + 1], newPaths[index]];
    setDictionaryPaths(newPaths);
  };
  const moveDictionaryToTop = (index: number) => {
    const newPaths = [...dictionaryPaths];
    const [removed] = newPaths.splice(index, 1);
    newPaths.unshift(removed);
    setDictionaryPaths(newPaths);
  };

  // 选择规则文件
  const chooseRuleFile = async () => {
    const result = await open({
      multiple: true,
      filters: [
        { name: isZh ? '所有文件' : 'All Files', extensions: ['*'] }
      ],
      title: isZh ? '选择规则文件' : 'Select Rule File'
    });
    
    if (result) {
      const paths = Array.isArray(result) ? result : [result];
      setRulePaths(prev => [...new Set([...prev, ...paths])]);
    }
  };

  // 选择掩码文件
  const chooseMaskFile = async () => {
    const result = await open({
      multiple: false,
      filters: [
        { name: isZh ? '所有文件' : 'All Files', extensions: ['*'] }
      ],
      title: isZh ? '选择掩码文件' : 'Select Mask File'
    });
    
    if (result) {
      setMaskPath(result as string);
      setCharsetEnabled(false);
    }
  };

  // 清空所有字典
  const clearDictionaryPaths = () => {
    setDictionaryPaths([]);
    setDictionaryPath("");
  };

  const clearRules = () => {
    setRulePaths([]);
    setRulePath("");
  };

  const removeRuleFromList = (path: string) => {
    setRulePaths(prev => prev.filter(p => p !== path));
  };

  return (
    <>
      <div className="modal-overlay" onClick={props.onClose}>
        <div className="custom-resource-modal" onClick={(e) => e.stopPropagation()}>
          {/* ========== 顶部标题栏 - 参考自定义资源样式 ========== */}
          <div className="modal-header">
            <div className="header-text">
              <p className="eyebrow">{isEditing ? "Edit Preset" : "Add Preset"}</p>
              <h2>{isEditing ? props.text.editPreset : props.text.addPreset}</h2>
            </div>
            <button type="button" onClick={props.onClose} className="icon-button">
              <X size={20} />
            </button>
          </div>
          {/* 警告消息 - 使用 settings-test warn 样式 */}
          {warnMessage && (
            <div className="settings-test warn">
              <span className="test-label">{warnMessage}</span>
            </div>
          )}
          {/* ========== 主体内容 ========== */}
          <div className="modal-body">
            {/* ========== 第一行：攻击类型、名称、描述 ========== */}
            <div className="preset-form-row">
              {/* 攻击类型选择器 */}
              <div className="form-group attack-mode-group">
                <label className="field-label">{props.text.attackModePicker}</label>
                <div className="attack-mode-dropdown-wrapper">
                  <div className="attack-mode-dropdown"  ref={dropdownRef}>
                    {/* 触发器按钮 - 添加点击事件切换下拉框状态 */}
                    <button 
                      className="attack-mode-dropdown-trigger" 
                      type="button" 
                      disabled={isEditing}
                      onClick={(e) => {
                        e.stopPropagation();
                        setAttackModeDropdownOpen(!attackModeDropdownOpen);
                      }}
                    >
                      <span>{attackModeLabel(attackMode, props.text)}</span>
                      <ChevronDown size={16} />
                    </button>
                    
                    {/* 下拉列表 - 根据状态显示/隐藏 */}
                    <div 
                      className={`attack-mode-list ${attackModeDropdownOpen ? 'open' : ''}`} 
                      onClick={(e) => e.stopPropagation()}
                    >
                      {([
                        { mode: 0 as AttackMode, label: props.text.dictionary },
                        { mode: 1 as AttackMode, label: props.text.dictionaryCombo },
                        { mode: 3 as AttackMode, label: props.text.mask },
                        { mode: 6 as AttackMode, label: props.text.hybridDictMask },
                        { mode: 7 as AttackMode, label: props.text.hybridMaskDict },
                        { mode: 9 as AttackMode, label: props.text.templateAttack },
                      ]).map((item) => (
                        <button
                          className={attackMode === item.mode ? "active" : ""}
                          key={item.mode}
                          type="button"
                          onClick={() => {
                            setAttackMode(item.mode);
                            // ========== 新增：选择后关闭下拉框 ==========
                            setAttackModeDropdownOpen(false);
                          }}
                        >
                          {item.label}
                          <span className="attack-mode-flag">(-a {item.mode === 9 ? "0" : item.mode})</span>
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
              
              {/* 名称输入框 */}
              <div className="form-group">
                <label className="field-label">{props.text.name} <span className="optional">({isZh ? "可选" : "optional"})</span></label>
                <input 
                  type="text" 
                  value={name} 
                  onChange={(e) => { setName(e.target.value); setWarnMessage(""); }} 
                  placeholder={isZh ? "预设名称" : "Preset name"}
                  className="form-input"
                />
              </div>
              
              {/* 描述输入框 */}
              <div className="form-group">
                <label className="field-label">{props.text.description} <span className="optional">({isZh ? "可选" : "optional"})</span></label>
                <input 
                  type="text" 
                  value={description} 
                  onChange={(e) => setDescription(e.target.value)} 
                  placeholder={isZh ? "预设描述" : "Preset description"}
                  className="form-input"
                />
              </div>
            </div>
            
            {/* ========== 攻击配置区域 ========== */}
            <div className="preset-config-section">
              {/* 字典模式 */}
              {attackMode === 0 && (
                <div className="config-panel">
                  <div className="dictionary-selector">
                    <div className="multi-dictionary-box">
                      <div className="line-title">
                        <span>{props.text.dictionaryFile}</span>
                        <button type="button" onClick={() => chooseDictionary()} className="add-btn">
                          <Plus size={14} />{props.text.add}
                        </button>
                        <button type="button" onClick={() => openResourcePicker("dictionary")}>
                          {props.text.useResource}
                        </button>
                        <button type="button" onClick={() => clearDictionaryPaths()} className="clear-btn">
                          {props.text.clear}
                        </button>
                        <label className="toggle-line rules-toggle inline">
                          <input 
                            type="checkbox" 
                            checked={useRules} 
                            onChange={(event) => setUseRules(event.currentTarget.checked)} 
                          />
                          <span>{props.text.useRules}</span>
                        </label>
                      </div>
                      
                      <div className="pill-list">
                        {dictionaryPaths.length > 0 ? (
                          dictionaryPaths.map((path, index) => (
                            <span className="path-pill" key={`${path}-${index}`} title={path}>
                              <span className="path-index">{index + 1}</span>
                              <span className="path-name">{path}</span>
                              <div className="path-actions">
                                <button 
                                  type="button" 
                                  onClick={() => moveDictionaryToTop(index)} 
                                  disabled={index === 0}
                                  title={isZh ? "置顶" : "Move to top"}
                                >
                                  <ArrowUpToLine size={12} />
                                </button>
                                <button 
                                  type="button" 
                                  onClick={() => moveDictionaryUp(index)} 
                                  disabled={index === 0}
                                  title={isZh ? "上移" : "Move up"}
                                >
                                  <ChevronUp size={12} />
                                </button>
                                <button 
                                  type="button" 
                                  onClick={() => moveDictionaryDown(index)} 
                                  disabled={index === dictionaryPaths.length - 1}
                                  title={isZh ? "下移" : "Move down"}
                                >
                                  <ChevronDown size={12} />
                                </button>
                                <button 
                                  type="button" 
                                  onClick={() => removeDictionaryFromList(path)} 
                                  title={isZh ? "删除" : "Remove"}
                                >
                                  <X size={12} />
                                </button>
                              </div>
                            </span>
                          ))
                        ) : dictionaryPath ? (
                          <span className="path-pill" key={dictionaryPath} title={dictionaryPath}>
                            <span className="path-index">1</span>
                            <span className="path-name">{dictionaryPath}</span>
                            <div className="path-actions">
                              <button type="button" onClick={clearDictionary} title={isZh ? "删除" : "Remove"}>
                                <X size={12} />
                              </button>
                            </div>
                          </span>
                        ) : (
                          <span className="muted">{props.text.notSelected}</span>
                        )}
                      </div>
                    </div>
                    {/* 每个字典生成一个预设选项 */}
                    <label className="toggle-line rules-toggle inline">
                      <input 
                        type="checkbox" 
                        checked={createPresetPerDictionary} 
                        onChange={(event) => setCreatePresetPerDictionary(event.currentTarget.checked)} 
                      />
                      <span>{props.text.eachDictCreatePreset}</span>
                    </label>
                    {useRules && (
                      <div className="rules-section">
                        <div className="line-title">
                          <span>{props.text.rule}</span>
                          <button type="button" onClick={() => { setRuleEditorTarget("left"); props.openRuleEditor("left"); setRuleEditorOpen(true); }}>
                            {props.text.ruleEditor}
                          </button>
                          <button type="button" onClick={() => openResourcePicker("rule", "primary", "left")}>
                            {props.text.useResource}
                          </button>
                        </div>
                        <div className="rules-input-section">
                          <div className="mask-input-wrapper">
                            <input 
                              className="mask-input" 
                              value={leftRule} 
                              onChange={(e) => setLeftRule(e.target.value)} 
                              placeholder={props.text.rulePlaceholder} 
                              spellCheck={false} 
                            />
                          </div>
                        </div>
                        <div className="line-title">
                          <span>{props.text.rulesFile}</span>
                          <button type="button" onClick={() => chooseRuleFile()} className="add-btn">
                            <Plus size={14} />{props.text.add}
                          </button>
                          <button type="button" onClick={() => openResourcePicker("rule")}>
                            {props.text.useResource}
                          </button>
                          <button type="button" onClick={() => clearRules()} className="clear-btn">
                            {props.text.clear}
                          </button>
                        </div>
                        
                        {/* 规则文件列表 */}
                        <div className="pill-list">
                          {rulePaths.length > 0 ? (
                            rulePaths.map((path, index) => (
                              <span className="path-pill" key={`${path}-${index}`} title={path}>
                                <span className="path-name">{path}</span>
                                <div className="path-actions">
                                  <button 
                                    type="button" 
                                    onClick={() => removeRuleFromList(path)} 
                                    title={isZh ? "删除" : "Remove"}
                                  >
                                    <X size={12} />
                                  </button>
                                </div>
                              </span>
                            ))
                          ) : rulePath ? (
                            <span className="path-pill" key={rulePath} title={rulePath}>
                              <span className="path-name">{rulePath}</span>
                              <div className="path-actions">
                                <button type="button" onClick={() => setRulePath("")} title={isZh ? "删除" : "Remove"}>
                                  <X size={12} />
                                </button>
                              </div>
                            </span>
                          ) : (
                            <span className="muted">{props.text.notSelected}</span>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
              
              {/* 字典组合模式 */}
              {attackMode === 1 && (
                <div className="config-panel">
                  <div className="side-by-side">
                    <div className="config-half">
                      <div className="file-section">
                        <label className="field-label">{props.text.dictionaryFile} 1</label>
                        <div className="file-input-row">
                          <input 
                            type="text" 
                            value={dictionaryPath} 
                            onChange={(e) => setDictionaryPath(e.target.value)} 
                            placeholder={props.text.notSelected}
                            className="file-input"
                          />
                          <button type="button" onClick={chooseDictionary} className="browse-btn">{props.text.browse}</button>
                          <button className="browse-btn" type="button" onClick={() => openResourcePicker("dictionary", "primary")}>
                            {props.text.useResource}
                          </button>
                        </div>
                        {dictionaryPath && (
                          <div className="clear-button-row">
                            <button type="button" onClick={clearDictionary} className="clear-btn full-width">{props.text.clear}</button>
                          </div>
                        )}
                        <label className="toggle-line rules-toggle">
                          <input 
                            type="checkbox" 
                            checked={useLeftRule} 
                            onChange={(e) => setUseLeftRule(e.target.checked)} 
                          />
                          <span>{props.text.useRules}</span>
                        </label>
                        {useLeftRule && (
                          <div className="rule-input-wrapper">
                            <input 
                              className="mask-input" 
                              value={leftRule} 
                              onChange={(e) => setLeftRule(e.target.value)} 
                              placeholder={props.text.leftRule} 
                              spellCheck={false} 
                            />
                            <button className="browse-btn" type="button" onClick={() => { setRuleEditorTarget("left"); props.openRuleEditor("left"); setRuleEditorOpen(true); }}>
                              {props.text.ruleEditor}
                            </button>
                            <button className="browse-btn" type="button" onClick={() => openResourcePicker("rule", "primary", "left")}>
                              {props.text.useResource}
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                    
                    <div className="config-half">
                      <div className="file-section">
                        <label className="field-label">{props.text.dictionaryFile} 2</label>
                        <div className="file-input-row">
                          <input 
                            type="text" 
                            value={dictionaryPath2} 
                            onChange={(e) => setDictionaryPath2(e.target.value)} 
                            placeholder={props.text.notSelected}
                            className="file-input"
                          />
                          <button type="button" onClick={chooseDictionary2} className="browse-btn">{props.text.browse}</button>
                          <button className="browse-btn" type="button" onClick={() => openResourcePicker("dictionary", "secondary")}>
                            {props.text.useResource}
                          </button>
                        </div>
                        {dictionaryPath2 && (
                          <div className="clear-button-row">
                            <button type="button" onClick={clearDictionary2} className="clear-btn full-width">{props.text.clear}</button>
                          </div>
                        )}
                        <label className="toggle-line rules-toggle">
                          <input 
                            type="checkbox" 
                            checked={useRightRule} 
                            onChange={(e) => setUseRightRule(e.target.checked)} 
                          />
                          <span>{props.text.useRules}</span>
                        </label>
                        {useRightRule && (
                          <div className="rule-input-wrapper">
                            <input 
                              className="mask-input" 
                              value={rightRule} 
                              onChange={(e) => setRightRule(e.target.value)} 
                              placeholder={props.text.rightRule} 
                              spellCheck={false} 
                            />
                            <button className="browse-btn" type="button" onClick={() => { setRuleEditorTarget("right"); props.openRuleEditor("right"); setRuleEditorOpen(true); }}>
                              {props.text.ruleEditor}
                            </button>
                            <button className="browse-btn" type="button" onClick={() => openResourcePicker("rule", "secondary", "right")}>
                              {props.text.useResource}
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              )}
              
              {/* 掩码模式 */}
              {attackMode === 3 && (
                <div className="config-panel">
                  <div className="mask-section">
                    <label className="field-label">{props.text.mask}</label>
                    <div className="mask-input-wrapper">
                      <div className="mask-input-row">
                        <input 
                          className="mask-input" 
                          value={mask} 
                          onChange={(e) => setMask(e.target.value)} 
                          placeholder={props.text.maskPlaceholder} 
                          spellCheck={false} 
                          disabled={!!maskPath}
                        />
                        <button type="button" onClick={() => setMaskHelp(!maskHelp)} className="help-btn">{props.text.help}</button>
                        <button type="button" onClick={() => chooseMaskFile()} className="browse-btn">
                          {props.text.browse}
                        </button>
                        <button className="browse-btn" type="button" onClick={() => openResourcePicker("mask")}>
                          {props.text.useResource}
                        </button>
                      </div>
                      {maskPath && (
                        <div className="mask-file-display">
                          <span className="mask-file-path">{maskPath}</span>
                          <button type="button" onClick={() => setMaskPath("")} className="clear-btn">
                            {props.text.clear}
                          </button>
                        </div>
                      )}
                      <div className="increment-toggle">
                        <label className="toggle-line">
                          <input 
                            type="checkbox" 
                            checked={increment}
                            onChange={(e) => setIncrement(e.target.checked)} 
                          />
                          <span>{props.text.incrementMask}</span>
                        </label>
                      </div>
                      {increment && (
                        <div className="increment-range-wrapper">
                          <div className="increment-field">
                            <span>{props.text.incrementMin}</span>
                            <input 
                              type="text" 
                              value={incrementMin} 
                              onChange={(e) => setIncrementMin(e.target.value.replace(/\D/g, "").slice(0, 2))} 
                              placeholder="1" 
                              className="increment-input"
                            />
                          </div>
                          <div className="increment-field">
                            <span>{props.text.incrementMax}</span>
                            <input 
                              type="text" 
                              value={incrementMax} 
                              onChange={(e) => setIncrementMax(e.target.value.replace(/\D/g, "").slice(0, 2))} 
                              placeholder="8" 
                              className="increment-input"
                            />
                          </div>
                        </div>
                      )}
                    </div>
                    
                  </div>
                  
                  <div className="charset-section">
                    <label className="toggle-line">
                      <input 
                        type="checkbox" 
                        checked={charsetEnabled && !maskPath}
                        onChange={(e) => setCharsetEnabled(e.target.checked)} 
                        disabled={!!maskPath}
                      />
                      <span>{props.text.customCharset}</span>
                    </label>
                    {charsetEnabled && (
                      <div className="charset-grid">
                        {["1", "2", "3", "4"].map(slot => (
                          <div key={slot} className="charset-item">
                            <span className="charset-label">?{slot}</span>
                            <input 
                              type="text" 
                              value={customCharsets[slot] || ""} 
                              onChange={(e) => setCustomCharsets(prev => ({ ...prev, [slot]: e.target.value }))} 
                              placeholder={isZh ? `字符集 ${slot}` : `Charset ${slot}`}
                              className="charset-input"
                            />
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {maskHelp && (
                    <div className="mask-help">
                      <p>{props.text.maskHelp}</p>
                      <code>JinriPIN_Salt_2015?d?d?d?d</code>
                    </div>
                  )}
                </div>
              )}
              
              {/* 字典+掩码模式 */}
              {attackMode === 6 && (
                <div className="config-panel">
                  <div className="side-by-side">
                    <div className="config-half">
                      <div className="file-section">
                        <label className="field-label">{props.text.dictionaryFile}</label>
                        <div className="file-input-row">
                          <input 
                            type="text" 
                            value={dictionaryPaths.length > 0 
                              ? isZh ? `已选择 ${dictionaryPaths.length} 个字典` : `${dictionaryPaths.length} dictionaries selected`
                              : dictionaryPath
                            } 
                            disabled={dictionaryPaths.length > 0}
                            onChange={(e) => setDictionaryPath(e.target.value)} 
                            placeholder={props.text.notSelected}
                            className="file-input"
                          />
                          <button type="button" onClick={chooseDictionary} className="browse-btn">{props.text.browse}</button>
                          <button className="browse-btn" type="button" onClick={() => openResourcePicker("dictionary", "primary")}>
                            {props.text.useResource}
                          </button>
                        </div>
                        {dictionaryPaths.length > 0 && (
                          <div className="hint-text">
                            {props.text.eachDictWillGeneratePreset}
                          </div>
                        )}
                        {dictionaryPath && (
                          <div className="clear-button-row">
                            <button type="button" onClick={clearDictionary} className="clear-btn full-width">{props.text.clear}</button>
                          </div>
                        )}
                        <label className="toggle-line rules-toggle">
                          <input 
                            type="checkbox" 
                            checked={useLeftRule} 
                            onChange={(e) => setUseLeftRule(e.target.checked)} 
                          />
                          <span>{props.text.useRules}</span>
                        </label>
                        {useLeftRule && (
                          <div className="rule-input-wrapper">
                            <input 
                              className="mask-input" 
                              value={leftRule} 
                              onChange={(e) => setLeftRule(e.target.value)} 
                              placeholder={props.text.leftRule} 
                              spellCheck={false} 
                            />
                            <button className="browse-btn" type="button" onClick={() => { setRuleEditorTarget("left"); props.openRuleEditor("left"); setRuleEditorOpen(true); }}>
                              {props.text.ruleEditor}
                            </button>
                            <button className="browse-btn" type="button" onClick={() => openResourcePicker("rule", "primary", "left")}>
                              {props.text.useResource}
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                    
                    <div className="config-half">
                      <div className="mask-section">
                        <label className="field-label">{props.text.mask}</label>
                        <div className="mask-input-wrapper">
                          <div className="mask-input-row">
                            <input 
                              className="mask-input" 
                              value={mask} 
                              onChange={(e) => setMask(e.target.value)} 
                              placeholder={props.text.maskPlaceholder} 
                              spellCheck={false} 
                            />
                            <button type="button" onClick={() => setMaskHelp(!maskHelp)} className="help-btn">{props.text.help}</button>
                            <button className="browse-btn" type="button" onClick={() => openResourcePicker("mask")}>
                              {props.text.useResource}
                            </button>
                          </div>
                          <div className="increment-toggle">
                            <label className="toggle-line">
                              <input 
                                type="checkbox" 
                                checked={increment} 
                                onChange={(e) => setIncrement(e.target.checked)} 
                              />
                              <span>{props.text.incrementMask}</span>
                            </label>
                          </div>
                          {increment && (
                            <div className="increment-range-wrapper">
                              <label className="increment-field">
                                <span>{props.text.incrementMin}</span>
                                <input 
                                  type="text" 
                                  value={incrementMin} 
                                  onChange={(e) => setIncrementMin(e.target.value.replace(/\D/g, "").slice(0, 2))} 
                                  placeholder="1" 
                                  className="increment-input"
                                />
                              </label>
                              <label className="increment-field">
                                <span>{props.text.incrementMax}</span>
                                <input 
                                  type="text" 
                                  value={incrementMax} 
                                  onChange={(e) => setIncrementMax(e.target.value.replace(/\D/g, "").slice(0, 2))} 
                                  placeholder="8" 
                                  className="increment-input"
                                />
                              </label>
                            </div>
                          )}
                        </div>
                        
                        <div className="charset-section">
                          <label className="toggle-line">
                            <input 
                              type="checkbox" 
                              checked={charsetEnabled} 
                              onChange={(e) => setCharsetEnabled(e.target.checked)} 
                            />
                            <span>{props.text.customCharset}</span>
                          </label>
                          {charsetEnabled && (
                            <div className="charset-grid-two-col">
                              {["1", "2", "3", "4"].map(slot => (
                                <div key={slot} className="charset-item">
                                  <span className="charset-label">?{slot}</span>
                                  <input 
                                    type="text" 
                                    value={customCharsets[slot] || ""} 
                                    onChange={(e) => setCustomCharsets(prev => ({ ...prev, [slot]: e.target.value }))} 
                                    placeholder={isZh ? `字符集 ${slot}` : `Charset ${slot}`}
                                    className="charset-input"
                                  />
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                        
                      </div>
                      {maskHelp && (
                        <div className="mask-help">
                          <p>{props.text.maskHelp}</p>
                          <code>JinriPIN_Salt_2015?d?d?d?d</code>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
              
              {/* 掩码+字典模式 */}
              {attackMode === 7 && (
                <div className="config-panel">
                  <div className="side-by-side">
                    <div className="config-half">
                      <div className="mask-section">
                        <label className="field-label">{props.text.mask}</label>
                        <div className="mask-input-wrapper">
                          <div className="mask-input-row">
                            <input 
                              className="mask-input" 
                              value={mask} 
                              onChange={(e) => setMask(e.target.value)} 
                              placeholder={props.text.maskPlaceholder} 
                              spellCheck={false} 
                            />
                            <button type="button" onClick={() => setMaskHelp(!maskHelp)} className="help-btn">{props.text.help}</button>
                            <button className="browse-btn" type="button" onClick={() => openResourcePicker("mask")}>
                              {props.text.useResource}
                            </button>
                          </div>
                          <div className="increment-toggle">
                            <label className="toggle-line">
                              <input 
                                type="checkbox" 
                                checked={increment} 
                                onChange={(e) => setIncrement(e.target.checked)} 
                              />
                              <span>{props.text.incrementMask}</span>
                            </label>
                          </div>
                          {increment && (
                            <div className="increment-range-wrapper">
                              <label className="increment-field">
                                <span>{props.text.incrementMin}</span>
                                <input 
                                  type="text" 
                                  value={incrementMin} 
                                  onChange={(e) => setIncrementMin(e.target.value.replace(/\D/g, "").slice(0, 2))} 
                                  placeholder="1" 
                                  className="increment-input"
                                />
                              </label>
                              <label className="increment-field">
                                <span>{props.text.incrementMax}</span>
                                <input 
                                  type="text" 
                                  value={incrementMax} 
                                  onChange={(e) => setIncrementMax(e.target.value.replace(/\D/g, "").slice(0, 2))} 
                                  placeholder="8" 
                                  className="increment-input"
                                />
                              </label>
                            </div>
                          )}
                        </div>
                        
                        <div className="charset-section">
                          <label className="toggle-line">
                            <input 
                              type="checkbox" 
                              checked={charsetEnabled} 
                              onChange={(e) => setCharsetEnabled(e.target.checked)} 
                            />
                            <span>{props.text.customCharset}</span>
                          </label>
                          {charsetEnabled && (
                            <div className="charset-grid-two-col">
                              {["1", "2", "3", "4"].map(slot => (
                                <div key={slot} className="charset-item">
                                  <span className="charset-label">?{slot}</span>
                                  <input 
                                    type="text" 
                                    value={customCharsets[slot] || ""} 
                                    onChange={(e) => setCustomCharsets(prev => ({ ...prev, [slot]: e.target.value }))} 
                                    placeholder={isZh ? `字符集 ${slot}` : `Charset ${slot}`}
                                    className="charset-input"
                                  />
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                      {maskHelp && (
                        <div className="mask-help">
                          <p>{props.text.maskHelp}</p>
                          <code>JinriPIN_Salt_2015?d?d?d?d</code>
                        </div>
                      )}
                    </div>
                    
                    <div className="config-half">
                      <div className="file-section">
                        <label className="field-label">{props.text.dictionaryFile}</label>
                        <div className="file-input-row">
                          <input 
                            type="text" 
                            value={dictionaryPaths.length > 0 
                              ? isZh ? `已选择 ${dictionaryPaths.length} 个字典` : `${dictionaryPaths.length} dictionaries selected`
                              : dictionaryPath
                            } 
                            disabled={dictionaryPaths.length > 0}
                            onChange={(e) => setDictionaryPath(e.target.value)} 
                            placeholder={props.text.notSelected}
                            className="file-input"
                          />
                          <button type="button" onClick={chooseDictionary} className="browse-btn">{props.text.browse}</button>
                          <button className="browse-btn" type="button" onClick={() => openResourcePicker("dictionary", "primary")}>
                            {props.text.useResource}
                          </button>
                        </div>
                        {dictionaryPaths.length > 0 && (
                          <div className="hint-text">
                            {props.text.eachDictWillGeneratePreset}
                          </div>
                        )}
                        {dictionaryPath && (
                          <div className="clear-button-row">
                            <button type="button" onClick={clearDictionary} className="clear-btn full-width">{props.text.clear}</button>
                          </div>
                        )}
                        <label className="toggle-line rules-toggle">
                          <input 
                            type="checkbox" 
                            checked={useRightRule} 
                            onChange={(e) => setUseRightRule(e.target.checked)} 
                          />
                          <span>{props.text.useRules}</span>
                        </label>
                        {useRightRule && (
                          <div className="rule-input-wrapper">
                            <input 
                              className="mask-input" 
                              value={rightRule} 
                              onChange={(e) => setRightRule(e.target.value)} 
                              placeholder={props.text.rightRule} 
                              spellCheck={false} 
                            />
                            <button className="browse-btn" type="button" onClick={() => { setRuleEditorTarget("right"); props.openRuleEditor("right"); setRuleEditorOpen(true); }}>
                              {props.text.ruleEditor}
                            </button>
                            <button className="browse-btn" type="button" onClick={() => openResourcePicker("rule", "secondary", "right")}>
                              {props.text.useResource}
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              )}
              
              {/* 模板攻击模式 */}
              {attackMode === 9 && (
                <div className="config-panel">
                  <div className="side-by-side">
                    <div className="config-half">
                      <div className="mask-section">
                        <label className="field-label">{props.text.prefixMask}</label>
                        <div className="mask-input-wrapper">
                          <input 
                            className="mask-input" 
                            value={prefixMask} 
                            onChange={(e) => setPrefixMask(e.target.value)} 
                            placeholder={isZh ? "前缀掩码" : "Prefix mask"} 
                            spellCheck={false} 
                          />
                        </div>
                      </div>
                    </div>
                    
                    <div className="config-half">
                      <div className="mask-section">
                        <label className="field-label">{props.text.suffixMask}</label>
                        <div className="mask-input-wrapper">
                          <input 
                            className="mask-input" 
                            value={suffixMask} 
                            onChange={(e) => setSuffixMask(e.target.value)} 
                            placeholder={isZh ? "后缀掩码" : "Suffix mask"} 
                            spellCheck={false} 
                          />
                        </div>
                      </div>
                    </div>
                    <button className="browse-btn template-browse-btn" type="button" onClick={() => openResourcePicker("template")}>
                      {props.text.useResource}
                    </button>
                  </div>
                  <div className="file-section">
                    <label className="field-label">{props.text.dictionaryFile}</label>
                    <div className="file-input-row">
                      <input 
                        type="text" 
                        value={dictionaryPath} 
                        onChange={(e) => setDictionaryPath(e.target.value)} 
                        placeholder={props.text.notSelected}
                        className="file-input"
                      />
                      <button type="button" onClick={chooseDictionary} className="browse-btn">{props.text.browse}</button>
                      <button className="browse-btn" type="button" onClick={() => openResourcePicker("dictionary", "primary")}>
                        {props.text.useResource}
                      </button>
                    </div>
                    {dictionaryPath && (
                      <div className="clear-button-row">
                        <button type="button" onClick={clearDictionary} className="clear-btn full-width">{props.text.clear}</button>
                      </div>
                    )}
                  </div>
                  {/* 自定义字符集设置 */}
                  <div className="charset-section">
                    <label className="toggle-line">
                      <input 
                        type="checkbox" 
                        checked={charsetEnabled} 
                        onChange={(e) => setCharsetEnabled(e.target.checked)} 
                      />
                      <span>{props.text.customCharset}</span>
                    </label>
                    {charsetEnabled && (
                      <div className="charset-grid">
                        {["1", "2", "3", "4"].map(slot => (
                          <div key={slot} className="charset-item">
                            <span className="charset-label">?{slot}</span>
                            <input 
                              type="text" 
                              value={customCharsets[slot] || ""} 
                              onChange={(e) => setCustomCharsets(prev => ({ ...prev, [slot]: e.target.value }))} 
                              placeholder={isZh ? `字符集 ${slot}` : `Charset ${slot}`}
                              className="charset-input"
                            />
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
          
          {/* 底部按钮栏 */}
          <div className="modal-footer">
            <button type="button" className="ghost-button" onClick={props.onClose}>
              {props.text.cancel}
            </button>
            <button type="button" className="primary-button" onClick={handleSave}>
              {props.text.save}
            </button>
          </div>
          
          {resourcePickerOpen && (
            <ResourcePickerModal
              isOpen={resourcePickerOpen}
              onClose={() => setResourcePickerOpen(false)}
              resourceKind={selectedResourceKind}
              ruleType={selectedRuleType}
              text={props.text}
              onUseResource={useResource}
              onUseCustomResource={useCustomResource}
              onUseUserDictionary={useUserDictionary}
              resources={props.resources}
              userDictionaries={props.userDictionaries}
              customResources={props.customResources}
              attackMode={attackMode}
            />
          )}
        </div>
      </div>
      {/* 规则编辑器弹窗 */}
      {ruleEditorOpen && (
        <RuleEditorModal
          isOpen={ruleEditorOpen}
          onClose={() => setRuleEditorOpen(false)}
          text={props.text}
          initialTarget={ruleEditorTarget}
          onApply={(rule, target) => {
            if (target === "right") {
              setUseRightRule(true);
              setRightRule(prev => (prev || "") + rule);
            } else {
              setUseLeftRule(true);
              setLeftRule(prev => (prev || "") + rule);
            }
            setRuleEditorOpen(false);
          }}
        />
      )}
    </>
  );
}

function HealthItem(props: { icon: ReactNode; label: string; value: string; tone: "ok" | "warn" }) {
  return <div className={`health-item ${props.tone}`}>{props.icon}<span>{props.label}</span><strong>{props.value}</strong></div>;
}

function filterModes(modes: HashModeInfo[], query: string) {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return modes;
  return modes.filter((mode) => `${mode.mode} ${mode.name} ${mode.category} ${mode.keywords.join(" ")}`.toLowerCase().includes(normalized));
}

function recommendHashModes(hashText: string, modes: HashModeInfo[]): HashModeSuggestion[] {
  const sample = firstHashSample(hashText);
  if (!sample) return [];
  const add = (items: Array<Omit<HashModeSuggestion, "name">>) => items
    .map((item) => ({
      ...item,
      name: modes.find((mode) => String(mode.mode) === item.mode)?.name || fallbackHashModeName(item.mode),
    }))
    .filter((item, index, list) => list.findIndex((other) => other.mode === item.mode) === index)
    .slice(0, 4);

  if (/^WPA\*0[12]\*/i.test(sample)) {
    return add([{ mode: "22000", confidence: "high", reason: "WPA*01/WPA*02 hash line" }]);
  }
  if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(sample)) {
    return add([{ mode: "3200", confidence: "high", reason: "bcrypt $2a/$2b/$2y format" }]);
  }
  if (/^sha256:\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/i.test(sample)) {
    return add([{ mode: "10900", confidence: "medium", reason: "sha256:iterations:base64-salt:base64-hash format" }]);
  }
  if (/^\$1\$/.test(sample)) {
    return add([{ mode: "500", confidence: "high", reason: "md5crypt $1$ prefix" }]);
  }
  if (/^\$5\$/.test(sample)) {
    return add([{ mode: "7400", confidence: "high", reason: "sha256crypt $5$ prefix" }]);
  }
  if (/^\$6\$/.test(sample)) {
    return add([{ mode: "1800", confidence: "high", reason: "sha512crypt $6$ prefix" }]);
  }
  if (/^\$(P|H)\$/.test(sample)) {
    return add([{ mode: "400", confidence: "medium", reason: "phpass/phpBB style prefix" }]);
  }
  if (/^[a-f0-9]{32}$/i.test(sample)) {
    return add([
      { mode: "0", confidence: "medium", reason: "32 hex characters" },
      { mode: "1000", confidence: "low", reason: "NTLM is also 32 hex characters" },
    ]);
  }
  if (/^[a-f0-9]{40}$/i.test(sample)) {
    return add([{ mode: "100", confidence: "medium", reason: "40 hex characters" }]);
  }
  if (/^[a-f0-9]{64}$/i.test(sample)) {
    return add([{ mode: "1400", confidence: "medium", reason: "64 hex characters" }]);
  }
  if (/^[a-f0-9]{128}$/i.test(sample)) {
    return add([{ mode: "1700", confidence: "medium", reason: "128 hex characters" }]);
  }
  return [];
}

function firstHashSample(hashText: string) {
  const line = hashText
    .split(/\r?\n/)
    .map((item) => item.trim())
    .find((item) => item && !item.startsWith("#"));
  if (!line) return "";
  const withoutUsername = line.match(/^[^:$]{1,80}:([a-f0-9]{32,128})$/i)?.[1];
  return withoutUsername || line;
}

function fallbackHashModeName(mode: string) {
  const names: Record<string, string> = {
    "0": "MD5",
    "100": "SHA1",
    "400": "phpass / WordPress",
    "500": "md5crypt",
    "1000": "NTLM",
    "1400": "SHA2-256",
    "1700": "SHA2-512",
    "1800": "sha512crypt",
    "3200": "bcrypt",
    "7400": "sha256crypt",
    "10900": "PBKDF2-HMAC-SHA256",
    "22000": "WPA-PBKDF2-PMKID+EAPOL",
  };
  return names[mode] || `Hash mode ${mode}`;
}

function confidenceLabel(value: HashModeSuggestion["confidence"], text: UiText) {
  if (value === "high") return text.confidenceHigh;
  if (value === "medium") return text.confidenceMedium;
  return text.confidenceLow;
}


function buildPreview(config: Pick<AttackConfig, "attackMode" | "increment" | "incrementMin" | "incrementMax" | "customCharset1" | "customCharset2" | "customCharset3" | "customCharset4" | "charsetFile1" | "charsetFile2" | "charsetFile3" | "charsetFile4" | "deviceIds" | "deviceTypes" | "dictionaryPath" | "dictionaryPath2" | "leftRule" | "rightRule" | "hashFile" | "hashMode" | "hashText" | "mask" | "maskFile" | "templatePrefixMask" | "templateSuffixMask" | "optimizedKernel" | "rulePaths" | "workloadProfile"> & {
  useLeftRule?: boolean;
  useRightRule?: boolean;
}) {
  const parts = ["hashcat.exe", "--status", "--status-json", "--status-timer=1", "-m", config.hashMode || "<mode>", "-a", config.attackMode === 9 ? "0" : String(config.attackMode)];
  if (config.optimizedKernel) parts.push("-O");
  parts.push("-w", String(config.workloadProfile ?? 3));
  if (config.increment && [3, 6, 7].includes(config.attackMode)) {
    parts.push("--increment");
    if (config.incrementMin) parts.push("--increment-min", String(config.incrementMin));
    if (config.incrementMax) parts.push("--increment-max", String(config.incrementMax));
  }
  if (config.deviceTypes?.length) parts.push("-D", config.deviceTypes.join(","));
  if (config.deviceIds?.trim()) parts.push("-d", config.deviceIds.trim());
  [
    config.charsetFile1 || config.customCharset1,
    config.charsetFile2 || config.customCharset2,
    config.charsetFile3 || config.customCharset3,
    config.charsetFile4 || config.customCharset4
  ].forEach((value, index) => {
    if (value?.trim()) parts.push(`-${index + 1}`, quote(value.trim()));
  });
  if (config.attackMode === 0) {
      config.rulePaths?.forEach((rule) => parts.push("-r", quote(rule)));
      // 字典模式添加左规则 -j
      if (config.useLeftRule && config.leftRule?.trim()) parts.push("-j", quote(config.leftRule.trim()));
  }
  parts.push(config.hashText?.trim() ? "<pasted-hash.tmp>" : quote(config.hashFile || "<hash-file>"));
  const wordlist = quote(config.dictionaryPath || "<wordlist>");
  const maskValue = config.attackMode === 3 ? (config.maskFile || config.mask || "<mask>") : (config.mask || "<mask>");
  const mask = quote(maskValue);
  if (config.attackMode === 0) parts.push(wordlist);
  if (config.attackMode === 1) {
    const leftDict = quote(config.dictionaryPath || "<left-dict>");
    const rightDict = quote(config.dictionaryPath2 || "<right-dict>");
    parts.push(leftDict, rightDict);
    // 只有勾选使用左规则时才添加
    if (config.useLeftRule && config.leftRule?.trim()) parts.push("-j", quote(config.leftRule.trim()));
    // 只有勾选使用右规则时才添加
    if (config.useRightRule && config.rightRule?.trim()) parts.push("-k", quote(config.rightRule.trim()));
  }
  if (config.attackMode === 3) parts.push(mask);
  if (config.attackMode === 6) {
    parts.push(wordlist, mask);
    if (config.useLeftRule && config.leftRule?.trim()) parts.push("-j", quote(config.leftRule.trim()));
  }
  if (config.attackMode === 7) {
    parts.push(mask, wordlist);
    if (config.useRightRule && config.rightRule?.trim()) parts.push("-k", quote(config.rightRule.trim()));
  }
  if (config.attackMode === 9) parts.push("<generated_candidates.txt>");
  return parts.join(" ");
}

// 提取任务使用的字典和掩码信息，用于列表显示
function extractResourceInfo(
  config: Pick<AttackConfig, "attackMode" | "dictionaryPath" | "dictionaryPath2" | "mask" | "maskFile" | "templatePrefixMask" | "templateSuffixMask" | "leftRule" | "rightRule" | "rulePaths" | "increment" | "incrementMin" | "incrementMax" | "customCharset1" | "customCharset2" | "customCharset3" | "customCharset4">,
  candidates?: bigint | number | null,
  isChinese = true,
  isEstimated?: boolean
): string {
  const getFileName = (path?: string | null) => {
    if (!path?.trim()) return "";
    return path.split(/[\\/]/).pop() || "";
  };

  const mask = config.attackMode === 3
    ? ((config.maskFile ? getFileName(config.maskFile) : "") || config.mask?.trim() || "")
    : (config.mask?.trim() || "");
  const dict1 = getFileName(config.dictionaryPath);
  const dict2 = getFileName(config.dictionaryPath2);
  
  // 获取规则信息
  const getRuleInfo = () => {
    const leftRuleStr = config.leftRule || "";
    const rightRuleStr = config.rightRule || "";
    const ruleFiles = config.rulePaths?.map(p => getFileName(p)) || [];
    
    const combinedStrings: string[] = [];
    if (leftRuleStr) combinedStrings.push(leftRuleStr);
    if (rightRuleStr) combinedStrings.push(rightRuleStr);
    combinedStrings.push(...ruleFiles);
    
    const combined = combinedStrings.length === 0 ? "" : combinedStrings.join(" + ");
    
    return { left: leftRuleStr, right: rightRuleStr, combined };
  };

  // 获取自定义字符集信息
  const getCharsetInfo = () => {
    const charsets: string[] = [];
    if (config.customCharset1) charsets.push(`-1 ${config.customCharset1}`);
    if (config.customCharset2) charsets.push(`-2 ${config.customCharset2}`);
    if (config.customCharset3) charsets.push(`-3 ${config.customCharset3}`);
    if (config.customCharset4) charsets.push(`-4 ${config.customCharset4}`);
    if (charsets.length === 0) return "";
    return charsets.join(", ");
  };

  // 获取递增掩码信息
  const getIncrementInfo = () => {
    if (!config.increment) return "";
    const min = config.incrementMin;
    const max = config.incrementMax;
    const hasMin = min !== undefined && min !== null;
    const hasMax = max !== undefined && max !== null;
    return `{${hasMin ? min : ""},${hasMax ? max : ""}}`;
  };

  const ruleInfo = getRuleInfo();
  const charsetInfo = getCharsetInfo();
  const incrementInfo = getIncrementInfo();

  let candidatesStr = "";
  if (candidates) {
    const estimatePrefix = isEstimated ? "≈" : "";  // 估算时添加 ≈ 符号
    candidatesStr = `(${estimatePrefix}${formatCandidateCount(candidates, isChinese)}) `;
  }


  switch (config.attackMode) {
    case 0: // 字典攻击
      return `${candidatesStr}${dict1 || "?"}${ruleInfo.combined ? ` [${ruleInfo.combined}]` : ""}`;
    
    case 1: // 字典组合
      const dict1WithRule = dict1 + (ruleInfo.left ? ` [${ruleInfo.left}]` : "");
      const dict2WithRule = dict2 + (ruleInfo.right ? ` [${ruleInfo.right}]` : "");
      const dictPart = [dict1WithRule, dict2WithRule].filter(Boolean).join(" + ");
      return `${candidatesStr}${dictPart || "?"}`;
    
    case 3: // 掩码攻击
      const mask3Parts = [mask || "?"];
      if (incrementInfo) mask3Parts.push(incrementInfo);
      if (charsetInfo) mask3Parts.push(`[${charsetInfo}]`);
      return `${candidatesStr}${mask3Parts.join(" ")}`;
    
    case 6: // 字典+掩码
      const mask6Parts = [mask];
      if (incrementInfo) mask6Parts.push(incrementInfo);
      if (charsetInfo) mask6Parts.push(`[${charsetInfo}]`);
      const mask6Str = mask6Parts.filter(Boolean).join(" ");
      return `${candidatesStr}${dict1 || ""}${ruleInfo.combined ? ` [${ruleInfo.combined}]` : ""}${dict1 && mask ? " + " : ""}${mask6Str || ""}` || "?";
    
    case 7: // 掩码+字典
      const mask7Parts = [mask];
      if (incrementInfo) mask7Parts.push(incrementInfo);
      if (charsetInfo) mask7Parts.push(`[${charsetInfo}]`);
      const mask7Str = mask7Parts.filter(Boolean).join(" ");
      return `${candidatesStr}${mask7Str || ""}${dict1 ? " + " : ""}${dict1 || ""}${ruleInfo ? ` [${ruleInfo}]` : ""}` || "?";
    
    case 9: // 模板攻击
      const prefix = config.templatePrefixMask?.trim() || "";
      const suffix = config.templateSuffixMask?.trim() || "";
      return `${candidatesStr}${[prefix, dict1 || "<dict>", suffix].filter(Boolean).join(" + ")}` || "?";
    
    default:
      return "-";
  }
}

function quote(value: string) {
  return value.includes(" ") ? `"${value}"` : value;
}

function shortPath(path: string) {
  const parts = path.replace(/\\/g, "/").split("/");
  return parts.length <= 3 ? path : `${parts[0]}/.../${parts[parts.length - 2]}/${parts[parts.length - 1]}`;
}

function formatSize(size: number) {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 * 1024 * 1024) return `${(size / 1024 / 1024).toFixed(1)} MB`;
  return `${(size / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

function formatDateTime(value?: string) {
  if (!value) return "-";
  // 处理 Unix 时间戳（数字字符串）
  const timestamp = Number(value);
  const date = Number.isNaN(timestamp) ? new Date(value) : new Date(timestamp);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatTaskDate(value?: string) {
  if (!value) return "-";
  const timestamp = Number(value);
  const date = Number.isNaN(timestamp) ? new Date(value) : new Date(timestamp);
  if (Number.isNaN(date.getTime())) return value;
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  return `${year}/${month}/${day} ${hours}:${minutes}`;
}

function mergeUpdateLog(current: HashcatUpdateEvent[], next: HashcatUpdateEvent) {
  const normalized = {
    ...next,
    line: compactUpdateLine(next.line),
  };
  const index = current.findIndex((item) => item.phase === normalized.phase);
  if (index < 0) return [...current.slice(-8), normalized];
  return current.map((item, itemIndex) => itemIndex === index ? normalized : item);
}

function compactUpdateLine(line: string) {
  return line.replace(/\s+/g, " ").trim();
}

function appendAiDelta(current: string, delta: string) {
  if (!delta) return current;
  if (current.endsWith(delta)) return current;
  if (delta.startsWith(current) && delta.length > current.length) return delta;
  return current + delta;
}

function normalizeAiAnalysisText(text: string) {
  if (!text) return "";

  let next = text.replace(/\r\n?/g, "\n");
  if (hasAiDuplicateArtifacts(next)) {
    next = collapseRepeatedCjk(next);
    next = collapseRepeatedTechnicalTokens(next);
    next = collapseRepeatedTextRuns(next);
    next = collapseRepeatedTechnicalTokens(next);
  }

  next = next
    .split("\n")
    .map((line) => line.replace(/[ \t]+$/g, "").replace(/[ \t]{2,}/g, " "))
    .join("\n")
    .replace(/\n[ \t]+/g, "\n")
    .replace(/\n{3,}/g, "\n\n");

  return collapseRepeatedAdjacentLines(next);
}

function hasAiDuplicateArtifacts(text: string) {
  const cjkPairs = countMatches(text, /([\u3400-\u9fff])\1/g);
  const repeatedWords = countMatches(text, /\b([A-Za-z][A-Za-z0-9_-]{1,24})\s+\1\b/g);
  const repeatedFragments = countMatches(text, /([A-Za-z][A-Za-z0-9_.-]{1,15})\1/g);
  return cjkPairs >= 3
    || repeatedWords >= 2
    || repeatedFragments >= 3
    || /\b(task|hash|attack|status|mode|rockyou)\s+\1_/i.test(text);
}

function countMatches(text: string, pattern: RegExp) {
  return text.match(pattern)?.length ?? 0;
}

function collapseRepeatedCjk(text: string) {
  return text
    .replace(/([\u3400-\u9fff])\s+\1(?=[\u3400-\u9fff])/g, "$1")
    .replace(/([\u3400-\u9fff])\1/g, "$1")
    .replace(/([：，。、；！？])\1/g, "$1");
}

function collapseRepeatedTechnicalTokens(text: string) {
  return text
    .replace(/\b([A-Za-z][A-Za-z0-9-]{1,24})\s+\1_([A-Za-z0-9_]+)/g, "$1_$2")
    .replace(/_([A-Za-z0-9]{2,24})_\1\b/g, "_$1")
    .replace(/\.([A-Za-z0-9]{1,8})\.\1\b/g, ".$1")
    .replace(/\b([A-Za-z][A-Za-z0-9_-]{1,24})\s+\1\b/g, "$1")
    .replace(/(^|[\s：:])--([mawDOr])\2\b/g, "$1-$2")
    .replace(/(^|[\s：:])-([mawDOr])\s+([0-9])\3\b/g, "$1-$2 $3")
    .replace(/\btask--/g, "task-");
}

function collapseRepeatedTextRuns(text: string) {
  const chars = Array.from(text);
  let output = "";
  let index = 0;

  while (index < chars.length) {
    let replaced = false;
    const maxLen = Math.min(24, Math.floor((chars.length - index) / 2));
    for (let len = maxLen; len >= 2; len -= 1) {
      const left = chars.slice(index, index + len).join("");
      if (!/[A-Za-z0-9_.-]|[\u3400-\u9fff]/.test(left)) continue;
      const right = chars.slice(index + len, index + len * 2).join("");
      if (left === right) {
        output += left;
        index += len * 2;
        replaced = true;
        break;
      }
    }
    if (!replaced) {
      output += chars[index];
      index += 1;
    }
  }

  return output;
}

function collapseRepeatedAdjacentLines(text: string) {
  const lines = text.split("\n");
  const output: string[] = [];
  let previous = "";

  for (const line of lines) {
    const normalized = line.trim();
    if (normalized && normalized === previous) continue;
    output.push(line);
    previous = normalized || "";
  }

  return output.join("\n");
}

// 格式化 MAC 地址（大写，冒号分隔）
function formatMacAddress(hex: string): string {
  if (!hex || hex.length !== 12) return hex;
  return hex.match(/.{2}/g)?.join(':').toUpperCase() || hex;
}

// 标准化 hash 内容，用于比对
function normalizeHashContent(content: string | undefined | null): string {
  if (!content) return "";
  // 去除空白字符、排序每行、去除空行
  return content
    .trim()
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line)
    .sort()
    .join("\n");
}

// 检测hash是否已被破解
async function checkHashAlreadyCracked(hashContent: string, tasksList: TaskManifest[]): Promise<string | null> {
  if (!hashContent.trim()) return null;
  
  const normalizedHash = normalizeHashContent(hashContent);
  
  // 获取所有已破解的任务
  const crackedTasks = tasksList.filter(task => 
    task.status === "cracked" && 
    task.extractedPasswords && 
    task.extractedPasswords.length > 0
  );
  
  for (const task of crackedTasks) {
    // 尝试从任务中获取hashContent
    let taskHashContent = task.config.hashText || "";
    
    // 如果没有hashText，尝试读取hashFile
    if (!taskHashContent && task.config.hashFile) {
      try {
        const response = await invoke<FilePreviewResponse>("preview_text_file", {
          path: task.config.hashFile,
          allowFull: true
        });
        taskHashContent = response.content || "";
      } catch {
        continue;
      }
    }
    
    const normalizedTaskHash = normalizeHashContent(taskHashContent);
    
    // 比较hash内容
    if (normalizedTaskHash && normalizedTaskHash === normalizedHash) {
      return task.taskId;
    }
  }
  
  return null;
}

// 解析 WPA hash 内容，提取 ESSID 和 BSSID
function parseWpaHashInfo(hashContent: string): { essids: string[]; bssids: string[] } {
  const essids: string[] = [];
  const bssids: string[] = [];
  const lines = hashContent.trim().split(/\r?\n/).filter(line => line.trim());

  for (const line of lines) {
    const parts = line.split('*');

    // 验证基本格式：至少需要 6 段（WPA*type*hash*bssid*ap_mac*essid*...）
    if (parts.length < 6) continue;

    // 验证第一段：固定为 WPA
    if (parts[0] !== "WPA") continue;

    // 验证第二段：type 必须为 01 或 02
    const type = parts[1];
    if (type !== "01" && type !== "02") continue;

    // 验证第 4 段：BSSID 必须是 12 位十六进制字符
    const bssidHex = parts[3];
    if (!/^[0-9A-Fa-f]{12}$/.test(bssidHex)) continue;

    // 验证第 6 段：ESSID 必须是偶数长度（0~64 位十六进制字符，即 0~32 字节）
    const essidHex = parts[5];
    if (essidHex.length % 2 !== 0 || essidHex.length > 64) continue;

    // 验证 ESSID 是有效的十六进制字符串
    if (essidHex.length > 0 && !/^[0-9A-Fa-f]*$/.test(essidHex)) continue;

    // 解析 ESSID（十六进制转字符串）
    let essid = "";
    try {
      if (essidHex.length > 0) {
        const bytes = [];
        for (let i = 0; i < essidHex.length; i += 2) {
          bytes.push(parseInt(essidHex.substr(i, 2), 16));
        }
        essid = new TextDecoder('utf-8').decode(new Uint8Array(bytes));
      }
    } catch {
      essid = "Unknown";
    }

    // 格式化 BSSID
    const bssid = formatMacAddress(bssidHex);

    // 添加到列表（去重）
    if (essid && !essids.includes(essid)) essids.push(essid);
    if (bssid && !bssids.includes(bssid)) bssids.push(bssid);
  }

  return { essids, bssids };
}

function attackModeLabel(mode: AttackMode, text: UiText) {
  const labels: Record<AttackMode, string> = {
    0: text.dictionary,
    1: text.dictionaryCombo,
    3: text.mask,
    6: text.hybridDictMask,
    7: text.hybridMaskDict,
    9: text.templateAttack,
  };
  return labels[mode];
}

// 生成预设详情显示字符串（可复用，避免重复计算）
function generatePresetDetail(preset: PresetConfig, text: UiText, isZh: boolean): string {
  const getFileName = (path?: string | null) => {
    if (!path?.trim()) return "";
    return path.split(/[\\/]/).pop() || "";
  };

  const dictName = preset.dictionaryPaths?.length 
    ? preset.dictionaryPaths.map(p => getFileName(p)).join(", ")
    : getFileName(preset.dictionaryPath);
  const config = preset as unknown as { maskFile?: string };
  const maskName = getFileName(preset.maskPath) || getFileName(config.maskFile) || preset.mask;

  // 获取候选数量
  const getDictCandidates = (): { candidates: bigint; isEstimated: boolean } | undefined => {
    if (preset.candidates != null) {
      return { 
        candidates: BigInt(preset.candidates), 
        isEstimated: preset.isEstimated || false 
      };
    }
    return undefined;
  };

  const dictCandidates = getDictCandidates();
  const candidatesStr = dictCandidates 
    ? `(${dictCandidates.isEstimated ? "≈" : ""}${formatCandidateCount(dictCandidates.candidates, isZh)}) `
    : "";

  // 获取规则信息
  const getRuleInfo = () => {
    const ruleConfig = preset as unknown as { useRules?: boolean; useLeftRule?: boolean; useRightRule?: boolean };
    
    // 只有当规则开关启用时才显示规则信息
    const hasEnabledRules = ruleConfig.useRules || ruleConfig.useLeftRule || ruleConfig.useRightRule;
    if (!hasEnabledRules) return { left: "", right: "", combined: "" };
    
    // 在字典攻击模式（attackMode === 0）下，使用 useRules 判断左规则
    // 在其他模式下，使用 useLeftRule 判断左规则
    const isDictAttack = preset.attackMode === 0;
    const leftRuleEnabled = isDictAttack ? ruleConfig.useRules : ruleConfig.useLeftRule;
    const leftRuleStr = leftRuleEnabled && preset.leftRule ? preset.leftRule : "";
    const rightRuleStr = ruleConfig.useRightRule && preset.rightRule ? preset.rightRule : "";
    
    const ruleFiles = ruleConfig.useRules && preset.rulePaths 
      ? preset.rulePaths.map(p => getFileName(p)) 
      : [];
    
    const combinedStrings: string[] = [];
    if (leftRuleStr) combinedStrings.push(leftRuleStr);
    if (rightRuleStr) combinedStrings.push(rightRuleStr);
    combinedStrings.push(...ruleFiles);
    
    const combined = combinedStrings.length === 0 ? "rules" : combinedStrings.join(" + ");
    
    return { left: leftRuleStr, right: rightRuleStr, combined };
  };
  
  // 获取递增掩码信息
  const getIncrementInfo = () => {
    if (!preset.increment) return "";
    const min = preset.incrementMin;
    const max = preset.incrementMax;
    const hasMin = min !== undefined && min !== null && min !== "";
    const hasMax = max !== undefined && max !== null && max !== "";
    return `{${hasMin ? min : ""},${hasMax ? max : ""}}`;
  };
  
  // 获取自定义字符集信息
  const getCharsetInfo = () => {
    const charsets: string[] = [];
    const config = preset as unknown as { customCharset1?: string; customCharset2?: string; customCharset3?: string; customCharset4?: string; customCharsets?: Record<string, string> };
    
    // 检查 AttackConfig 中的字符集属性
    if (config.customCharset1) charsets.push(`-1 ${config.customCharset1}`);
    if (config.customCharset2) charsets.push(`-2 ${config.customCharset2}`);
    if (config.customCharset3) charsets.push(`-3 ${config.customCharset3}`);
    if (config.customCharset4) charsets.push(`-4 ${config.customCharset4}`);
    
    // 检查 PresetConfig 中的字符集属性
    if (preset.customCharsets) {
      Object.entries(preset.customCharsets).forEach(([key, value]) => {
        if (value) charsets.push(`-${key} ${value}`);
      });
    }
    
    if (charsets.length === 0) return "";
    
    return `[${charsets.join(", ")}]`;
  };

  const ruleInfo = getRuleInfo();
  const incrementInfo = getIncrementInfo();
  const charsetInfo = getCharsetInfo();
  
  switch (preset.attackMode) {
    case 0: // 字典攻击
      return `${candidatesStr}${dictName || text.notSelected}${ruleInfo.combined ? ` [${ruleInfo.combined}]` : ""}`;
    case 1: // 字典组合
      const dict2Name = getFileName(preset.dictionaryPath2);
      const dict1WithRule = dictName + (ruleInfo.left ? ` [${ruleInfo.left}]` : "");
      const dict2WithRule = dict2Name + (ruleInfo.right ? ` [${ruleInfo.right}]` : "");
      const dictPart = [dict1WithRule, dict2WithRule].filter(Boolean).join(" + ");
      return `${candidatesStr}${dictPart || text.notSelected}`;
    case 3: // 掩码攻击
      const maskParts = [maskName || text.notSelected];
      if (incrementInfo) maskParts.push(incrementInfo);
      if (charsetInfo) maskParts.push(charsetInfo);
      return `${candidatesStr}${maskParts.join(" ")}`;
    case 6: // 字典+掩码
      const mask6Parts = [maskName];
      if (incrementInfo) mask6Parts.push(incrementInfo);
      if (charsetInfo) mask6Parts.push(charsetInfo);
      return `${candidatesStr}${dictName || ""}${ruleInfo.combined ? ` [${ruleInfo.combined}]` : ""}${dictName && maskName ? " + " : ""}${mask6Parts.filter(Boolean).join(" ") || ""}` || text.notSelected;
    case 7: // 掩码+字典
      const mask7Parts = [maskName];
      if (incrementInfo) mask7Parts.push(incrementInfo);
      if (charsetInfo) mask7Parts.push(charsetInfo);
      return `${candidatesStr}${mask7Parts.filter(Boolean).join(" ") || ""}${dictName ? " + " : ""}${dictName || ""}${ruleInfo.combined ? ` [${ruleInfo.combined}]` : ""}` || text.notSelected;
    case 9: // 模板攻击
      const config9 = preset as unknown as { templatePrefixMask?: string; templateSuffixMask?: string };
      const prefix = preset.prefixMask || config9.templatePrefixMask || "";
      const suffix = preset.suffixMask || config9.templateSuffixMask || "";
      return `${candidatesStr}${[prefix, dictName || "<dict>", suffix].filter(Boolean).join(" + ")}${charsetInfo ? ` ${charsetInfo}` : ""}` || text.notSelected;
    default:
      return text.notSelected;
  }
}

function resourceKindLabel(kind: ResourceInfo["kind"], text: UiText) {
  const labels: Record<ResourceInfo["kind"], string> = {
    rule: text.rulesFile,
    mask: text.mask,
    charset: "Charset",
    dictionary: text.dictionaryFile,
  };
  return labels[kind];
}

function resourceDescription(resource: ResourceInfo, text: UiText) {
  if (resource.kind === "rule") return text.resourceRuleHelp;
  if (resource.kind === "mask") return text.resourceMaskHelp;
  if (resource.kind === "charset") return text.resourceCharsetHelp;
  return text.resourceDictionaryHelp;
}

function canPreviewResource(resource: ResourceInfo) {
  return resource.kind === "rule" || resource.kind === "dictionary" || resource.kind === "mask" || resource.kind === "charset";
}

function normalizeHelpConfig(config: AiHashConsultConfig): AiHashConsultConfig {
  return {
    hashMode: config.hashMode ?? "",
    attackMode: config.attackMode,
    hashText: config.hashText ?? "",
    hashFile: config.hashFile ?? "",
    mask: config.mask ?? "",
    dictionaryPath: config.dictionaryPath ?? "",
    rulePaths: Array.isArray(config.rulePaths) ? config.rulePaths : [],
    question: config.question ?? "",
  };
}

function normalizeAiSettings(settings: AiSettings): AiSettings {
  return {
    baseUrl: settings.baseUrl ?? "",
    apiKey: settings.apiKey ?? "",
    model: settings.model ?? "",
  };
}

function parseAiSuggestedConfig(content: string): AiSuggestedConfig | null {
  const blocks = [...content.matchAll(/```(?:json)?\s*([\s\S]*?)```/gi)].map((match) => match[1]);
  for (const block of blocks.reverse()) {
    const parsed = parseAiSuggestionObject(block);
    if (parsed) return parsed;
  }

  const looseConfigIndex = content.lastIndexOf("hashcatGuiTaskConfig");
  if (looseConfigIndex >= 0) {
    const jsonText = extractJsonObjectAround(content, looseConfigIndex);
    if (jsonText) {
      const parsed = parseAiSuggestionObject(jsonText);
      if (parsed) return parsed;
    }
  }

  const marker = "HASHCAT_GUI_TASK_CONFIG:";
  const markerIndex = content.lastIndexOf(marker);
  if (markerIndex >= 0) {
    const parsed = parseAiSuggestionObject(content.slice(markerIndex + marker.length));
    if (parsed) return parsed;
  }

  return null;
}

function extractJsonObjectAround(text: string, index: number) {
  const start = text.lastIndexOf("{", index);
  if (start < 0) return "";

  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i += 1) {
    const char = text[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if (char === "\"") {
      inString = !inString;
      continue;
    }
    if (inString) continue;
    if (char === "{") depth += 1;
    if (char === "}") {
      depth -= 1;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }

  return "";
}

function parseAiSuggestionObject(text: string): AiSuggestedConfig | null {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end <= start) return null;

  try {
    const value = JSON.parse(text.slice(start, end + 1));
    const raw = value.hashcatGuiTaskConfig ?? value.taskConfig ?? value;
    const suggestion: AiSuggestedConfig = {};
    if (typeof raw.hashMode === "string" || typeof raw.hashMode === "number") suggestion.hashMode = String(raw.hashMode);
    if (isAttackMode(raw.attackMode)) suggestion.attackMode = raw.attackMode;
    if (typeof raw.hashText === "string") suggestion.hashText = raw.hashText;
    if (typeof raw.hashFile === "string") suggestion.hashFile = raw.hashFile;
    if (typeof raw.mask === "string") suggestion.mask = raw.mask;
    if (typeof raw.dictionaryPath === "string") suggestion.dictionaryPath = raw.dictionaryPath;
    if (Array.isArray(raw.rulePaths)) suggestion.rulePaths = raw.rulePaths.filter((path: unknown): path is string => typeof path === "string");
    return Object.keys(suggestion).length ? suggestion : null;
  } catch {
    return null;
  }
}

function isAttackMode(value: unknown): value is AttackMode {
  return value === 0 || value === 3 || value === 6 || value === 7 || value === 9;
}

function isHelpAiTask(taskId: string) {
  return taskId.startsWith("help-ai-");
}

function workloadInfo(value: number, text: UiText) {
  const data: Record<number, { label: string; description: string }> = {
    1: { label: text.workloadLow, description: text.performanceLowDesc },
    2: { label: text.workloadDefault, description: text.performanceDefaultDesc },
    3: { label: text.workloadHigh, description: text.performanceHighDesc },
    4: { label: text.workloadExtreme, description: text.performanceExtremeDesc },
  };
  return data[value] ?? data[3];
}

type TelemetryDevice = {
  name: string;
  type: string;
  speed: string;
  temperature: string;
  utilization: string;
  memory: string;
};

type BackendDevice = {
  id: string;
  name: string;
  type: string;
  backend: string;
  vendor: string;
  memory: string;
  processor: string;
};

function extractBackendDevices(info: Record<string, unknown> | null, raw: string): BackendDevice[] {
  const fromJson = findObjectDevices(info)
    .map((item, index) => normalizeBackendDevice(item, index, {}))
    .filter(Boolean) as BackendDevice[];
  if (fromJson.length) return dedupeBackendDevices(fromJson).slice(0, 8);

  return parseBackendRawDevices(raw).slice(0, 8);
}

function findObjectDevices(value: unknown, context: Partial<BackendDevice> = {}): Record<string, unknown>[] {
  if (!value || typeof value !== "object") return [];
  if (Array.isArray(value)) {
    return value.flatMap((item) => findObjectDevices(item, context));
  }
  const object = value as Record<string, unknown>;
  const keys = Object.keys(object).map((key) => key.toLowerCase());
  const looksLikeDevice = keys.some((key) => key.includes("deviceid") || key === "device" || key.includes("adapter") || key.includes("memory") || key.includes("processor"))
    && keys.some((key) => key.includes("name") || key.includes("type") || key.includes("memory") || key.includes("vendor"));
  const nextContext = {
    ...context,
    backend: inferBackendFromObject(object) || context.backend || "",
    vendor: stringifyMetric(pickValue(object, ["vendor", "vendor_name", "vendorName"])) || context.vendor || "",
  };
  const current = looksLikeDevice ? [{ ...object, __backend: nextContext.backend, __vendor: nextContext.vendor }] : [];
  return [
    ...current,
    ...Object.entries(object).flatMap(([key, item]) => findObjectDevices(item, {
      ...nextContext,
      backend: inferBackendFromKey(key) || nextContext.backend,
    })),
  ];
}

function normalizeBackendDevice(item: Record<string, unknown>, index: number, fallback: Partial<BackendDevice>): BackendDevice | null {
  const id = normalizeDeviceId(stringifyMetric(pickValue(item, ["device_id", "deviceId", "DeviceID", "id"])));
  const name = stringifyMetric(pickValue(item, ["name", "device_name", "deviceName", "alias", "device"])) || (id ? `hashcat 设备 ${id}` : `hashcat 设备 ${index + 1}`);
  const type = stringifyMetric(pickValue(item, ["type", "device_type", "deviceType"])) || inferDeviceType(name);
  const backend = stringifyMetric(pickValue(item, ["backend", "backend_type", "backendType", "api", "__backend"])) || fallback.backend || "";
  const vendor = stringifyMetric(pickValue(item, ["vendor", "vendor_name", "vendorName", "__vendor"])) || fallback.vendor || inferVendor(name);
  const memory = formatBackendMemory(pickValue(item, ["memory", "memory_total", "memoryTotal", "global_mem", "globalMemory", "vram", "MemoryTotal"]));
  const processor = stringifyMetric(pickValue(item, ["processor", "processors", "cores", "compute_units", "computeUnits"]));
  if (!name && !type && !backend && !vendor && !memory) return null;
  return { id, name, type, backend, vendor, memory, processor };
}

function parseBackendRawDevices(raw: string): BackendDevice[] {
  const lines = raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const interesting = lines.filter((line) => /device|backend|cuda|opencl|vulkan|nvidia|intel|amd|memory|processor/i.test(line));
  const chunks = interesting.length ? interesting : lines;
  return chunks.slice(0, 8).map((line, index) => ({
    id: normalizeDeviceId(line.match(/(?:device\s*(?:id)?|#)\s*[:#]?\s*(\d+)/i)?.[1] ?? ""),
    name: prettifyBackendLine(line) || `Device ${index + 1}`,
    type: /cpu/i.test(line) ? "CPU" : /gpu|cuda|opencl|vulkan/i.test(line) ? "GPU" : "",
    backend: line.match(/CUDA|OpenCL|Vulkan|HIP/i)?.[0] ?? "",
    vendor: line.match(/NVIDIA|Intel|AMD|Apple/i)?.[0] ?? "",
    memory: line.match(/\d+(?:\.\d+)?\s*(?:MB|GB|MiB|GiB)/i)?.[0] ?? "",
    processor: line.match(/\d+\s*(?:MCU|CU|processors?|cores?)/i)?.[0] ?? "",
  }));
}

function prettifyBackendLine(line: string) {
  return line
    .replace(/[{}[\]",]/g, " ")
    .replace(/\s+/g, " ")
    .replace(/^\d+\s*[:|-]\s*/, "")
    .trim()
    .slice(0, 96);
}

function dedupeBackendDevices(devices: BackendDevice[]) {
  const seen = new Set<string>();
  return devices.filter((device) => {
    const key = `${device.id}|${device.name}|${device.backend}|${device.vendor}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function formatBackendMemory(value: unknown): string {
  if (Array.isArray(value)) return value.map(formatBackendMemory).filter(Boolean).join(" / ");
  if (typeof value === "number") return value > 1024 * 1024 ? formatSize(value) : `${value} MB`;
  return stringifyMetric(value);
}

function estimateAttackMask(config: {
  attackMode: AttackMode;
  mask: string;
  templatePrefixMask: string;
  templateSuffixMask: string;
  customCharsets: string[];
  speedHps?: number;
  text: UiText;
  increment?: boolean;
  incrementMin?: string;
  incrementMax?: string;
}): MaskEstimate | null {
  if (![3, 6, 7, 9].includes(config.attackMode)) return null;
  const maskText = config.attackMode === 9
    ? `${config.templatePrefixMask}${config.templateSuffixMask}`
    : config.mask;
  if (!maskText.trim()) return null;
  
  let totalCandidates: bigint | undefined;
  
  if (config.increment) {
    // 递增掩码：计算从最小值到最大值的所有长度的候选数之和
    
    // 首先找到所有掩码位置的起始索引（不包括固定字符串和转义问号）
    const maskPositions: number[] = [];
    for (let i = 0; i < maskText.length; i++) {
      if (maskText[i] === "?") {
        if (maskText[i + 1] === "?") {
          // 转义问号，跳过两个字符
          i++;
        } else if (maskText[i + 1]) {
          // 有效的掩码位置，记录起始索引
          maskPositions.push(i);
          i++; // 跳过掩码字符
        }
      }
    }
    
    const maskPositionCount = maskPositions.length;
    const minLength = parseInt(config.incrementMin || "1", 10) || 1;
    const maxLength = parseInt(config.incrementMax || String(maskPositionCount), 10) || maskPositionCount;
    
    // 确保最小值不大于最大值
    const effectiveMin = Math.min(minLength, maxLength);
    const effectiveMax = Math.min(Math.max(minLength, maxLength), maskPositionCount);
    
    totalCandidates = 0n;
    for (let positionCount = effectiveMin; positionCount <= effectiveMax; positionCount++) {
      // 获取前 positionCount 个掩码位置的范围
      const startIndex = maskPositions[0];
      const endIndex = maskPositions[positionCount - 1] + 2; // +2 是因为每个掩码占2个字符
      
      // 截取这部分掩码（包括中间的固定字符串和转义问号）
      const truncatedMask = maskText.slice(startIndex, endIndex);
      const parsed = estimateMaskCandidates(truncatedMask, config.customCharsets);
      if (parsed.candidates) {
        totalCandidates += parsed.candidates;
      }
    }
    
    // 如果没有计算出任何候选数，返回 null
    if (totalCandidates === 0n) {
      totalCandidates = undefined;
    }
  } else {
    // 普通掩码：直接计算
    const parsed = estimateMaskCandidates(maskText, config.customCharsets);
    totalCandidates = parsed.candidates;
  }
  
  const speed = config.speedHps && config.speedHps > 0 ? config.speedHps : undefined;
  const estimatedSeconds = totalCandidates && speed ? bigIntToSeconds(totalCandidates, speed) : undefined;
  const partial = config.attackMode === 6 || config.attackMode === 7 || config.attackMode === 9;
  return {
    candidates: totalCandidates,
    estimatedSeconds,
    speedHps: speed,
    error: totalCandidates === undefined ? config.text.maskEstimateUnsupported : undefined,
    warning: partial ? config.text.maskEstimatePartial : undefined,
  };
}

function estimateMaskCandidates(maskText: string, customCharsets: string[] = []): { candidates?: bigint; error?: boolean } {
  const sizes: Record<string, bigint> = {
    l: 26n,
    u: 26n,
    d: 10n,
    h: 16n,
    H: 16n,
    s: 33n,
    a: 95n,
    b: 256n,
  };
  let total = 1n;
  for (let index = 0; index < maskText.length; index += 1) {
    const char = maskText[index];
    
    // 如果不是问号，跳过（固定字符串，不参与计算）
    if (char !== "?") {
      continue;
    }
    
    const token = maskText[index + 1];
    
    // 如果没有下一个字符，说明掩码不完整
    if (!token) {
      return { error: true };
    }
    
    // 如果是 ??，表示转义的问号（单个问号字符），跳过这两个字符
    if (token === "?") {
      index += 1;
      continue;
    }
    
    // 处理真正的掩码字符
    const size = sizes[token] ?? customCharsetSize(customCharsets[Number(token) - 1], sizes);
    if (!size) {
      return { error: true };
    }
    total *= size;
    index += 1;
  }
  return { candidates: total };
}

function customCharsetSize(value: string | undefined, baseSizes: Record<string, bigint>): bigint | undefined {
  const text = value?.trim();
  if (!text) return undefined;
  let total = 0n;
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] !== "?") {
      total += 1n;
      continue;
    }
    const token = text[index + 1];
    if (!token) return undefined;
    if (token === "?") {
      total += 1n;
      index += 1;
      continue;
    }
    const size = baseSizes[token];
    if (!size) return undefined;
    total += size;
    index += 1;
  }
  return total || undefined;
}

function extractStatusSpeed(status: Record<string, unknown> | null): number | undefined {
  if (!status) return undefined;
  const values: number[] = [];
  collectSpeedValues(status, values);
  const positive = values.filter((value) => Number.isFinite(value) && value > 0);
  return positive.length ? positive.reduce((sum, value) => sum + value, 0) : undefined;
}

function collectSpeedValues(value: unknown, output: number[]) {
  if (Array.isArray(value)) {
    for (const item of value) collectSpeedValues(item, output);
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    const lower = key.toLowerCase();
    if (lower.includes("speed")) {
      const speed = numericSpeed(item);
      if (speed) output.push(speed);
    }
    collectSpeedValues(item, output);
  }
}

function numericSpeed(value: unknown): number | undefined {
  if (typeof value === "number") return value;
  if (Array.isArray(value)) {
    const values = value.map(numericSpeed).filter((item): item is number => Boolean(item));
    return values.length ? values.reduce((sum, item) => sum + item, 0) : undefined;
  }
  if (typeof value !== "string") return undefined;
  const match = value.replace(/,/g, "").match(/([\d.]+)\s*([kmgth]?)[hH]?\/?s?/);
  if (!match) return undefined;
  const base = Number(match[1]);
  if (!Number.isFinite(base)) return undefined;
  const unit = match[2].toLowerCase();
  const factor = unit === "t" ? 1_000_000_000_000 : unit === "g" ? 1_000_000_000 : unit === "m" ? 1_000_000 : unit === "k" ? 1_000 : 1;
  return base * factor;
}

function bigIntToSeconds(candidates: bigint, speedHps: number): number {
  if (candidates <= 0n || speedHps <= 0) return 0;
  const maxSafe = BigInt(Number.MAX_SAFE_INTEGER);
  if (candidates > maxSafe) {
    const digits = candidates.toString().length;
    const approximate = Number(candidates.toString().slice(0, 15)) * 10 ** (digits - 15);
    return approximate / speedHps;
  }
  return Number(candidates) / speedHps;
}

function shouldConfirmLongTask(estimate: MaskEstimate | null) {
  return Boolean(estimate?.estimatedSeconds && estimate.estimatedSeconds >= 3600);
}

function extractStatusDevices(status: Record<string, unknown> | null, isChinese: boolean = false): TelemetryDevice[] {
  if (!status) return [];
  const candidates = findArrays(status).filter((array) =>
    array.some((item) => item && typeof item === "object" && (
      "speed" in item || "speed_dev" in item || "temperature" in item || "temp" in item || "util" in item || "device_name" in item
    )),
  );
  const source = candidates[0] ?? [];
  return source
    .filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object" && !Array.isArray(item))
    .slice(0, 8)
    .map((item, index) => ({
      name: stringifyMetric(pickValue(item, ["device_name", "name", "device", "alias"])) || `Device ${index + 1}`,
      type: stringifyMetric(pickValue(item, ["device_type", "type", "backend"])) || "",
      speed: formatSpeed(pickValue(item, ["speed", "speed_dev", "speed_sec", "speed_raw"]), isChinese),
      temperature: formatTemperature(pickValue(item, ["temperature", "temp", "temp_dev", "hardware_monitor_temperature"])),
      utilization: formatPercent(pickValue(item, ["util", "utilization", "util_dev", "hardware_monitor_utilization"])),
      memory: formatMemory(pickValue(item, ["memory", "memory_used", "vram", "vram_used", "hardware_monitor_memory"])),
    }));
}

function findArrays(value: unknown): Array<Record<string, unknown>[]> {
  if (!value || typeof value !== "object") return [];
  if (Array.isArray(value)) return [value as Record<string, unknown>[]];
  return Object.values(value as Record<string, unknown>).flatMap(findArrays);
}

function pickValue(object: Record<string, unknown>, keys: string[]) {
  const entries = Object.entries(object);
  for (const key of keys) {
    const value = object[key] ?? entries.find(([entryKey]) => entryKey.toLowerCase() === key.toLowerCase())?.[1];
    if (value !== undefined && value !== null && value !== "") return value;
  }
  return undefined;
}

function inferBackendFromObject(object: Record<string, unknown>) {
  const keys = Object.keys(object).join(" ").toLowerCase();
  const text = `${keys} ${stringifyMetric(pickValue(object, ["name", "version", "backend"]))}`.toLowerCase();
  if (text.includes("cuda")) return "CUDA";
  if (text.includes("opencl")) return "OpenCL";
  if (text.includes("vulkan")) return "Vulkan";
  if (text.includes("hip")) return "HIP";
  return "";
}

function inferBackendFromKey(key: string) {
  if (/cuda/i.test(key)) return "CUDA";
  if (/opencl/i.test(key)) return "OpenCL";
  if (/vulkan/i.test(key)) return "Vulkan";
  if (/hip/i.test(key)) return "HIP";
  return "";
}

function inferDeviceType(name: string) {
  return /gpu|nvidia|radeon|geforce|intel\(r\) uhd|arc/i.test(name) ? "GPU" : /cpu|processor/i.test(name) ? "CPU" : "";
}

function inferVendor(name: string) {
  if (/nvidia|geforce|cuda/i.test(name)) return "NVIDIA";
  if (/intel/i.test(name)) return "Intel";
  if (/amd|radeon/i.test(name)) return "AMD";
  return "";
}

function normalizeDeviceId(value: string) {
  return value.replace(/^0+(\d)/, "$1");
}

function stringifyMetric(value: unknown): string {
  if (Array.isArray(value)) return value.map(stringifyMetric).filter(Boolean).join(" / ");
  if (typeof value === "number" || typeof value === "string") return String(value);
  return "";
}

function formatSpeed(value: unknown, isChinese: boolean = false): string {
  if (Array.isArray(value)) return value.map(v => formatSpeed(v, isChinese)).filter((item) => item !== "--").join(" / ") || "--";
  if (typeof value === "number") {
    if (isChinese) {
      // 中文单位：不到1千正常显示，1千到1万显示"千"，1万以上显示"万"
      if (value < 1000) return `${value} 次/秒`;
      if (value < 10000) return `${(value / 1000).toFixed(2).replace(/\.0+$/, '')}千/秒`;
      return `${(value / 10000).toFixed(3).replace(/\.0+$/, '').replace(/(\.[1-9]*)0+$/, '$1')}万/秒`;
    } else {
      return `${formatNumber(value)} H/s`;
    }
  }
  const text = stringifyMetric(value);
  return text || "--";
}

function formatTemperature(value: unknown): string {
  if (Array.isArray(value)) return value.map(formatTemperature).filter((item) => item !== "--").join(" / ") || "--";
  if (typeof value === "number") return `${value} °C`;
  const text = stringifyMetric(value);
  return text ? (text.includes("°") || text.toLowerCase().includes("c") ? text : `${text} °C`) : "--";
}

function formatPercent(value: unknown): string {
  if (Array.isArray(value)) return value.map(formatPercent).filter((item) => item !== "--").join(" / ") || "--";
  if (typeof value === "number") return `${value}%`;
  const text = stringifyMetric(value);
  return text ? (text.includes("%") ? text : `${text}%`) : "--";
}

function formatMemory(value: unknown): string {
  if (Array.isArray(value)) return value.map(formatMemory).filter((item) => item !== "--").join(" / ") || "--";
  if (typeof value === "number") return value > 1024 * 1024 ? formatSize(value) : `${value} MB`;
  return stringifyMetric(value) || "--";
}

function formatNumber(value: number) {
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(2)}G`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(2)}K`;
  return String(value);
}

// 格式化大数字，根据语言使用不同单位
function formatCandidateCount(count: bigint | number, isChinese: boolean): string {
  const num = typeof count === 'bigint' ? Number(count) : count;
  
  if (num < 1000) return String(num);
  
  if (isChinese) {
    // 中文单位：千、万、亿、千亿、万亿
    if (num < 10000) return `${(num / 1000).toFixed(2).replace(/\.0+$/, '')}千`;
    if (num < 100000000) return `${(num / 10000).toFixed(2).replace(/\.0+$/, '')}万`;
    if (num < 100000000000) return `${(num / 100000000).toFixed(2).replace(/\.0+$/, '')}亿`;
    if (num < 1000000000000) return `${(num / 100000000000).toFixed(2).replace(/\.0+$/, '')}千亿`;
    return `${(num / 1000000000000).toFixed(2).replace(/\.0+$/, '')}万亿`;
  } else {
    // 英文单位：k(10^3), M(10^6), G(10^9), T(10^12)
    if (num < 1000000) return `${(num / 1000).toFixed(2).replace(/\.0+$/, '')}k`;
    if (num < 1000000000) return `${(num / 1000000).toFixed(2).replace(/\.0+$/, '')}M`;
    if (num < 1000000000000) return `${(num / 1000000000).toFixed(2).replace(/\.0+$/, '')}G`;
    return `${(num / 1000000000000).toFixed(2).replace(/\.0+$/, '')}T`;
  }
}

function numberOrNull(value: string) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function formatBigInt(value: bigint) {
  return value.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function formatDuration(seconds: number) {
  if (!Number.isFinite(seconds)) return "> 999 days";
  if (seconds < 1) return "< 1s";
  const rounded = Math.ceil(seconds);
  const days = Math.floor(rounded / 86400);
  const hours = Math.floor((rounded % 86400) / 3600);
  const minutes = Math.floor((rounded % 3600) / 60);
  const secs = rounded % 60;
  if (days > 999) return "> 999 days";
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutes) return `${minutes}m ${secs}s`;
  return `${secs}s`;
}

function formatRemainingTime(seconds: number, zh: boolean): string {
  if (!Number.isFinite(seconds) || seconds < 0) return zh ? "计算中..." : "Calculating...";
  const rounded = Math.ceil(seconds);
  const days = Math.floor(rounded / 86400);
  const hours = Math.floor((rounded % 86400) / 3600);
  const minutes = Math.floor((rounded % 3600) / 60);
  const secs = rounded % 60;
  
  const parts: string[] = [];
  if (days > 0) parts.push(zh ? `${days}天` : `${days}d`);
  if (hours > 0) parts.push(zh ? `${hours}小时` : `${hours}h`);
  if (minutes > 0) parts.push(zh ? `${minutes}分` : `${minutes}m`);
  if (secs > 0 || parts.length === 0) parts.push(zh ? `${secs}秒` : `${secs}s`);
  
  return parts.join(zh ? "" : " ");
}

function TaskProgressBar(props: {
  item: QueueItem;
  latestStatus: Record<string, unknown> | null;
  language: Language;
}) {
  const zh = props.language === "zh";
  const isRunning = props.item.status === "running";
  
  // 优先使用任务自己保存的进度信息，运行中的任务使用最新状态
  const progress = isRunning 
    ? (props.latestStatus?.progress as [number, number] | undefined)
    : props.item.progress;
  const estimatedStop = isRunning
    ? (props.latestStatus?.estimated_stop as number | undefined)
    : props.item.estimatedStop;
  
  // 计算进度百分比
  const progressPercent = progress && progress[1] > 0 
    ? ((progress[0] / progress[1]) * 100).toFixed(2) 
    : "0.00";
  
  // 计算剩余时间（仅运行中显示）
  const remainingSeconds = isRunning && estimatedStop 
    ? estimatedStop - Math.floor(Date.now() / 1000)
    : NaN;
  const remainingTime = formatRemainingTime(remainingSeconds, zh);
  
  return (
    <div className="task-progress-bar">
      <div className="progress-info">
        <span className="progress-label">{zh ? "进度" : "Progress"}</span>
        <div className="progress-bar-container">
          <div 
            className="progress-bar-fill" 
            style={{ width: `${Math.min(100, parseFloat(progressPercent))}%` }}
          />
        </div>
        <span className="progress-value">{progressPercent}%</span>
        {isRunning && (
          <span className="remaining-label">
            {zh ? "剩余时间：" : "Remaining: "}{remainingTime}
          </span>
        )}
      </div>
    </div>
  );
}

function customResourceValue(resource: CustomResource) {
  if (resource.type === "mask") {
    if (resource.mask) return ` ${resource.mask}`;
    if (resource.path) {
      const size = resource.size ? `${formatSize(resource.size)} · ` : "";
      return ` ${size}${shortPath(resource.path)}`;
    }
    return "";
  }
  if (resource.type === "charset") return ` ?${resource.charsetSlot ?? "1"} = ${resource.charsetValue ?? ""}`;
  if (resource.type === "dictionary") {
    if (resource.path) {
      const size = resource.size ? `${formatSize(resource.size)} · ` : "";
      return ` ${size}${shortPath(resource.path)}`;
    }
    return "";
  }
  if (resource.type === "rule") {
    if (resource.ruleValue && resource.ruleType) {
      // 手动输入的规则值，显示格式：-j 规则值 或 -k 规则值
      return ` ${resource.ruleType === "left" ? "-j" : "-k"} ${resource.ruleValue}`;
    }
    if (resource.path) {
      const size = resource.size ? `${formatSize(resource.size)} · ` : "";
      return ` ${size}${shortPath(resource.path)}`;
    }
    return "";
  }
  return ` ${resource.prefixMask || "<empty>"} + word + ${resource.suffixMask || "<empty>"}`;
}

function customResourceTypeLabel(resource: CustomResource, text: UiText) {
  const builtinSuffix = resource.isBuiltinCopy ? text.builtinEditableSuffix : "";
  if (resource.type === "mask") return (resource.isBuiltinCopy ? text.builtinMaskName : text.customMaskName) + builtinSuffix;
  if (resource.type === "charset") return text.customCharsetName;
  if (resource.type === "dictionary") return (resource.isBuiltinCopy ? text.builtinDictionaryName : text.customDictionaryName) + builtinSuffix;
  if (resource.type === "rule") {
    // 如果是手动输入的规则，显示左规则/右规则标签
    if (resource.ruleValue && resource.ruleType) {
      return resource.ruleType === "left" ? text.leftRule : text.rightRule;
    }
    // 否则显示自定义规则标签
    return (resource.isBuiltinCopy ? text.builtinRuleName : text.customRuleName) + builtinSuffix;
  }
  return text.customTemplateName;
}

function resourceTypeBadgeText(type: string, text: UiText): string {
  switch (type) {
    case "dictionary": return text.resourceDictionary || "Dict";
    case "mask": return text.resourceMask || "Mask";
    case "rule": return text.resourceRule || "Rule";
    case "charset": return text.resourceCharset || "Charset";
    case "template": return text.resourceTemplate || "Template";
    default: return type;
  }
}




function loadQueueItems(): QueueItem[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(TASK_QUEUE_STORAGE_KEY) || "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item): item is QueueItem =>
      typeof item?.id === "string" &&
      typeof item.name === "string" &&
      item.config &&
      typeof item.config.hashMode === "string" &&
      (item.status === "pending" || item.status === "running" || item.status === "skipped" || item.status === "stopped"),
    ).map((item) => {
      // 将字符串转换回 BigInt
      const candidates = item.candidates != null ? (typeof item.candidates === "string" ? BigInt(item.candidates) : item.candidates) : undefined;
      // 确保 isEstimated 字段被正确恢复（即使是 undefined 或 null）
      const isEstimated = item.isEstimated === true;
      return {
        ...item,
        candidates,
        isEstimated,
        status: item.status === "running" ? "pending" : item.status,
        taskId: item.status === "running" ? undefined : item.taskId,
      };
    });
  } catch {
    return [];
  }
}

// 保存任务名称映射
function saveTaskName(taskId: string, taskName: string) {
  try {
    const taskNames: Record<string, string> = JSON.parse(
      localStorage.getItem(TASK_NAMES_STORAGE_KEY) || "{}"
    );
    taskNames[taskId] = taskName;
    localStorage.setItem(TASK_NAMES_STORAGE_KEY, JSON.stringify(taskNames));
  } catch (e) {
    console.error("Failed to save task name:", e);
  }
}

// 加载任务名称映射
function loadTaskNames(): Record<string, string> {
  try {
    return JSON.parse(localStorage.getItem(TASK_NAMES_STORAGE_KEY) || "{}");
  } catch (e) {
    console.error("Failed to load task names:", e);
    return {};
  }
}

// 删除任务名称映射
function deleteTaskName(taskId: string) {
  try {
    const taskNames: Record<string, string> = JSON.parse(
      localStorage.getItem(TASK_NAMES_STORAGE_KEY) || "{}"
    );
    delete taskNames[taskId];
    localStorage.setItem(TASK_NAMES_STORAGE_KEY, JSON.stringify(taskNames));
  } catch (e) {
    console.error("Failed to delete task name:", e);
  }
}

function tabLabel(tab: TabKey, text: UiText) {
  const labels: Record<Exclude<TabKey, "queue">, string> = {
    config: text.tabConfig,
    resources: text.tabResources,
    history: text.tabHistory,
  };
  if (tab === "queue") return text.settingsTitle === "设置" ? "队列" : "Queue";
  return labels[tab];
}

function queueText(language: Language) {
  if (language === "zh") {
    return {
      add: "加入队列",
      title: "控制面板",
      hint: "多任务按顺序运行，一个结束后继续下一个。",
      start: "开始队列",
      pause: "暂停队列",
      skip: "跳过",
      restore: "恢复",
      remove: "移除",
      pending: "等待",
      running: "运行中",
      finished: "已完成",
      failed: "失败",
      skipped: "已跳过",
      stopped: "已暂停",
      empty: "队列暂无任务。在任务配置页点击加入队列。",
      added: "已加入队列",
      paused: "队列已暂停",
      resumed: "队列已开始",
      clearDone: "已清理完成项",
      clearDoneButton: "清理完成",
      pausedState: "队列暂停",
      activeState: "队列运行",
      ready: "就绪",
    };
  }
  return {
    add: "Add to Queue",
    title: "Control Panel",
    hint: "Run multiple tasks serially. The next task starts after the current one finishes.",
    start: "Start Queue",
    pause: "Pause Queue",
    skip: "Skip",
    restore: "Restore",
    remove: "Remove",
    pending: "Pending",
    running: "Running",
    finished: "Finished",
    failed: "Failed",
    skipped: "Skipped",
    stopped: "Stopped",
    empty: "No queued tasks. Add one from Task Config.",
    added: "Added to queue",
    paused: "Queue paused",
    resumed: "Queue started",
    clearDone: "Cleared completed tasks",
    clearDoneButton: "Clear Done",
    pausedState: "Paused",
    activeState: "Active",
    ready: "Ready",
  };
}

function queueStatusLabel(status: QueueStatus, language: Language) {
  const labels = queueText(language);
  const map: Record<QueueStatus, string> = {
    pending: labels.pending,
    running: labels.running,
    finished: labels.finished,
    failed: labels.failed,
    skipped: labels.skipped,
    stopped: labels.stopped,
  };
  return map[status];
}

function statusLabel(status: string, language: Language) {
  const zhStatus: Record<string, string> = {
    cracked: "已破解",
    exhausted: "已耗尽",
    aborted: "已中止",
    checkpoint: "检查点中止",
    finished: "已完成",
    running: "运行中",
    error: "错误",
    "backend-error": "错误",
    stopped: "已暂停",
  };
  return (language === "zh" ? zhStatus : STATUS_TEXT.en)[status] ?? status;
}
