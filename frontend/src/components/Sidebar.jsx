import { NavLink } from "react-router-dom";
import mainIcon from "../assets/main-icon.png";
import {
  LayoutDashboard,
  ShieldAlert,
  UploadCloud,
  FileText,
  Search,
  Flame,
  Network,
  Sliders,
  Sparkles,
  History,
  UserCheck,
} from "lucide-react";

const Sidebar = () => {
  const navItems = [
    { name: "Dashboard", path: "/dashboard", icon: LayoutDashboard },
    { name: "Log Explorer", path: "/logs", icon: Search },
    { name: "Security Alerts", path: "/alerts", icon: ShieldAlert },
    { name: "Incidents & Timeline", path: "/incidents", icon: Flame },
    { name: "IP Analysis", path: "/ips", icon: Network },
    { name: "Detection Rules", path: "/rules", icon: Sliders },
    { name: "AI Security Copilot", path: "/copilot", icon: Sparkles },
    { name: "Executive Reports", path: "/reports", icon: FileText },
    { name: "Analysis History", path: "/history", icon: History },
    { name: "Upload & Ingest", path: "/upload", icon: UploadCloud },
  ];

  return (
    <aside className="w-64 bg-surface border-r border-surface-light flex flex-col transition-all duration-300 relative z-20 shadow-lg shrink-0">
      <div className="h-16 flex items-center px-6 border-b border-surface-light bg-surface/50 backdrop-blur-sm">
        <div className="flex items-center gap-3 text-primary">
          <img
            src={mainIcon}
            alt="AI-Log Sentinel Logo"
            className="w-8 h-8 object-contain logo-icon"
          />
          <div>
            <span className="text-base font-black tracking-wider uppercase bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent">
              AI-Log Sentinel
            </span>
            <div className="text-[10px] tracking-widest text-text-muted font-mono uppercase">
              SOC Intelligence
            </div>
          </div>
        </div>
      </div>

      <nav className="flex-1 py-4 px-3 space-y-1 overflow-y-auto">
        {navItems.map((item) => (
          <NavLink
            key={item.name}
            to={item.path}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3.5 py-2.5 rounded-xl transition-all duration-200 group relative text-sm ${
                isActive
                  ? "bg-primary/10 text-primary font-semibold shadow-sm"
                  : "text-text-muted hover:bg-surface-light hover:text-text-main"
              }`
            }
          >
            {({ isActive }) => (
              <>
                {isActive && (
                  <div className="absolute left-0 top-1 bottom-1 w-1 bg-primary rounded-r-md"></div>
                )}
                <item.icon
                  className={`w-4 h-4 transition-colors shrink-0 ${isActive ? "text-primary" : "group-hover:text-primary"}`}
                />
                <span className="truncate">{item.name}</span>
              </>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="p-3 border-t border-surface-light space-y-2 bg-surface/80">
        <div className="bg-background/80 rounded-xl p-2.5 text-xs text-text-muted flex items-center justify-between border border-surface-light/50">
          <div className="flex items-center gap-2">
            <UserCheck className="w-4 h-4 text-primary" />
            <span className="text-text-main font-medium">SecAnalyst</span>
          </div>
          <span className="text-[10px] bg-primary/20 text-primary px-2 py-0.5 rounded-full font-mono font-bold">
            L2-SOC
          </span>
        </div>

        <div className="bg-background/40 rounded-lg px-3 py-1.5 text-[11px] text-text-muted flex items-center justify-between">
          <span>Engine Status:</span>
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full bg-primary animate-pulse"></div>
            <span className="text-primary font-medium">Ready</span>
          </div>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
