import { Info, GitBranch, ShieldAlert, Tag, X, RefreshCw } from "lucide-react";
import { createPortal } from "react-dom";
import pkg from "../../package.json"
import { useState } from "react";
import { UpdateDialog } from "./UpdateDialog";

type AboutDialogProps = {
  language: "zh" | "en";
  onClose: () => void;
  updateStatus: "idle" | "checking" | "latest" | "available";
  latestVersion: string;
  onCheckUpdate: () => void;
};

export function AboutDialog({ language, onClose, updateStatus, latestVersion, onCheckUpdate }: AboutDialogProps) {
  const zh = language === "zh";
  const [showUpdateDialog, setShowUpdateDialog] = useState(false);
  const [updateResult, setUpdateResult] = useState<{ hasUpdate: boolean; latest: string } | null>(null);

  return createPortal(
    <div className="modal-backdrop" role="presentation">
      <section className="settings-modal about-modal" role="dialog" aria-modal="true" aria-label={zh ? "关于" : "About"}>
        <div className="panel-heading">
          <div>
            <p className="eyebrow">About</p>
            <h2>hashcatGUI</h2>
            <span>{zh ? "面向 hashcat 的桌面图形控制台" : "Desktop GUI console for hashcat"}</span>
          </div>
          <button className="icon-button" type="button" onClick={onClose} aria-label={zh ? "关闭" : "Close"}>
            <X size={15} />
          </button>
        </div>

        <div className="about-profile">
          <div className="about-avatar"><Info size={24} /></div>
          <div>
            <strong>{zh ? "开发者" : "Developer"}：{pkg.author}</strong>
            <span>{zh ? "希望这个工具能让 hashcat 更好用、更直观。" : "Built to make hashcat easier and clearer to use."}</span>
          </div>
        </div>

        <div className="about-contact">
          <GitBranch size={17} />
          <div>
            <strong>{zh ? "开源地址" : "GitHub"}：<a href="https://github.com/wangdong0/hashcatGUI" target="_blank" rel="noopener noreferrer">github.com/wangdong0/hashcatGUI</a></strong>
            <span>{zh ? "欢迎 Star、Fork 和提交 Issue！" : "Welcome to Star, Fork and submit Issues!"}</span>
          </div>
        </div>

        <div className="about-contact">
          <Tag size={17} />
          <div className="about-version-row">
            <div className="about-version-info">
              <strong>
                {zh ? "版本信息" : "Version"}
                <button
                  className="update-check-btn"
                  onClick={() => {
                    onCheckUpdate();
                    const hasUpdate = latestVersion !== null && latestVersion !== pkg.version;
                    setUpdateResult({ hasUpdate, latest: latestVersion });
                    setShowUpdateDialog(true);
                  }}
                  disabled={updateStatus === "checking"}
                >
                  <RefreshCw size={14} className={updateStatus === "checking" ? "spin" : ""} />
                  {updateStatus === "checking" ? (zh ? "检查中..." : "Checking...") : (zh ? "检查更新" : "Check Update")}
                </button>
              </strong>
            </div>
            <span>
              v{pkg.version}
              {updateStatus === "latest" && ` (${zh ? "当前已是最新版本" : "Up to date"})`}
              {updateStatus === "available" && ` (${zh ? "发现新版本" : "Update available"}: v${latestVersion})`}
            </span>
          </div>
        </div>

        <div className="about-disclaimer">
          <ShieldAlert size={18} />
          <div>
            <strong>{zh ? "免责声明" : "Disclaimer"}</strong>
            <p>
              {zh
                ? "本工具仅用于授权安全测试、密码恢复、教学与学习研究。请勿在未授权的系统、账号或数据上使用。本工具开发者不对任何未授权使用、数据损失或法律风险承担责任。"
                : "This tool is only for authorized security testing, password recovery, education, and research. Do not use it on systems, accounts, or data without permission. The developer is not responsible for unauthorized use, data loss, or legal risk."}
            </p>
          </div>
        </div>
      </section>
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
    </div>,
    document.body,
  );
}
