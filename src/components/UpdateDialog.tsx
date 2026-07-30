import { Info, X, Download } from "lucide-react";
import { createPortal } from "react-dom";
import { openUrl } from "@tauri-apps/plugin-opener";

type UpdateDialogProps = {
  language: "zh" | "en";
  hasUpdate: boolean;
  latestVersion: string;
  currentVersion: string;
  onClose: () => void;
  onDownload: () => void;
};

export function UpdateDialog({ language, onClose, hasUpdate, latestVersion, currentVersion }: UpdateDialogProps) {
  const zh = language === "zh";

  return createPortal(
    <div className="modal-backdrop" role="presentation" onClick={onClose}>
      <section
        className="settings-modal about-modal"
        role="dialog"
        aria-modal="true"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: "420px" }}
      >
        <div className="panel-heading">
          <div>
            <p className="eyebrow">{zh ? "版本更新" : "Update"}</p>
            <h2>{hasUpdate ? (zh ? "发现新版本" : "Update Available") : (zh ? "已是最新版本" : "Up to Date")}</h2>
          </div>
          <button className="icon-button" type="button" onClick={onClose} aria-label={zh ? "关闭" : "Close"}>
            <X size={15} />
          </button>
        </div>

        <div className="update-content">
          <div className="update-avatar">
            <Info size={28} />
          </div>
          <div className="update-text">
            {hasUpdate ? (
              <>
                <p className="update-version">
                  {zh ? "最新版本" : "Latest"}: v{latestVersion}
                  <span className="update-status">
                    {zh ? "（发现新版本）" : "(New version available)"}
                  </span>
                </p>
                <p className="update-version">
                  {zh ? "当前版本" : "Current"}: v{currentVersion}
                </p>
              </>
            ) : (
              <p className="update-version">
                {zh ? "当前版本" : "Current"}: v{currentVersion}
                <span className="update-status update-status-latest">
                  {zh ? "（当前已是最新版本）" : "(Up to date)"}
                </span>
              </p>
            )}
          </div>
        </div>

        <div className="update-actions">
          {hasUpdate && (
            <button
              className="update-download-btn"
              onClick={async () => {
                await openUrl("https://github.com/wangdong0/hashcatGUI/releases");
              }}
            >
              <Download size={14} />
              {zh ? "前往下载" : "Download"}
            </button>
          )}
          <button className="update-close-btn" onClick={onClose}>
            {zh ? "关闭" : "Close"}
          </button>
        </div>
      </section>
    </div>,
    document.body,
  );
}