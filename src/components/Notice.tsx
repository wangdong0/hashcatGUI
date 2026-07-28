import { AlertTriangle, X } from "lucide-react";

type NoticeProps = {
  message: string;
  details?: string[];
  onClose: () => void;
};

export function Notice({ message, details = [], onClose }: NoticeProps) {
  return (
    <div className="notice" role="alert">
      <AlertTriangle size={17} />
      <div className="notice-body">
        <span>{message}</span>
        {details.length > 0 && (
          <ul>
            {details.map((item) => <li key={item}>{item}</li>)}
          </ul>
        )}
      </div>
      <button type="button" onClick={onClose} aria-label="Close">
        <X size={15} />
      </button>
    </div>
  );
}
