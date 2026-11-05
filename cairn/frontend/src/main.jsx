import React from "react";
import { createRoot } from "react-dom/client";
import { ConfigProvider } from "@arco-design/web-react";
import zhCN from "@arco-design/web-react/es/locale/zh-CN";
import App from "./App.jsx";
// Arco base styles first so the app's own styles.css can still override on conflicts.
import "@arco-design/web-react/dist/css/arco.css";
import "./styles.css";

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <ConfigProvider locale={zhCN}>
      <App />
    </ConfigProvider>
  </React.StrictMode>,
);
