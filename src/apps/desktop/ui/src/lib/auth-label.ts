import { t } from "@/lib/i18n";

/** Human label for a presence-path wire name (the `auth` a presence-gated
 * command returns). Unknown paths render as their wire name rather than
 * hiding which proof was used. */
export function authLabel(auth: string): string {
  switch (auth) {
    case "touch_id":
      return t("auth.touch_id");
    case "app_confirm":
      return t("auth.app_confirm");
    case "cli_confirm":
      return t("auth.cli_confirm");
    case "extension_confirm":
      return t("auth.extension_confirm");
    default:
      return auth;
  }
}
