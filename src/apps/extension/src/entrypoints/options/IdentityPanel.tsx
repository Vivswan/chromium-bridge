import { useI18n } from "@/hooks/useI18n";
import { AuthenticatorEnrollment } from "./AuthenticatorEnrollment";
import { HostPairing } from "./HostPairing";

export function IdentityPanel() {
  const { t } = useI18n();
  return (
    <div className="py-1">
      <div className="section-title mb-1.5">{t("identity.host_key_title")}</div>
      <HostPairing />
      <div className="section-title mt-6 mb-1.5">{t("identity.authenticator_title")}</div>
      <AuthenticatorEnrollment />
    </div>
  );
}
