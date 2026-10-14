import { useState, type FormEvent } from "react";
import { setToken } from "../auth";
import { Panel } from "./ui";

// Shown when the monitor answers 401: this device is not the monitor's own machine and has no valid token.
export function TokenPrompt() {
  const [value, setValue] = useState("");
  const save = (e: FormEvent) => {
    e.preventDefault();
    setToken(value.trim());
    window.location.reload();
  };
  return (
    <Panel title="API token required" className="token-panel">
      <p className="prose">
        This device is not the computer running NetSpectre, so the monitor asks for its API token before showing any
        data. It is the <span className="mono">NS_API_TOKEN</span> value in the monitor's <span className="mono">.env</span>{" "}
        file. The token is stored in this browser only.
      </p>
      <form className="lookup-form token-form" onSubmit={save}>
        <label htmlFor="api-token" className="sr-only">
          API token
        </label>
        <input
          id="api-token"
          type="password"
          autoComplete="off"
          spellCheck={false}
          placeholder="Paste the API token"
          value={value}
          onChange={(e) => setValue(e.target.value)}
        />
        <button type="submit" className="btn-primary" disabled={!value.trim()}>
          Save
        </button>
      </form>
    </Panel>
  );
}
