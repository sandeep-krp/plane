/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { useState } from "react";
import { isEmpty } from "lodash-es";
import Link from "next/link";
import { Controller, useForm } from "react-hook-form";
// plane internal packages
import { API_BASE_URL } from "@plane/constants";
import { Button, getButtonStyling } from "@plane/propel/button";
import { TOAST_TYPE, setToast } from "@plane/propel/toast";
import type { IFormattedInstanceConfiguration, TInstanceOidcAuthenticationConfigurationKeys } from "@plane/types";
import { TextArea, ToggleSwitch } from "@plane/ui";
// components
import { CodeBlock } from "@/components/common/code-block";
import { ConfirmDiscardModal } from "@/components/common/confirm-discard-modal";
import type { TControllerInputFormField } from "@/components/common/controller-input";
import { ControllerInput } from "@/components/common/controller-input";
import type { TControllerSwitchFormField } from "@/components/common/controller-switch";
import { ControllerSwitch } from "@/components/common/controller-switch";
import type { TCopyField } from "@/components/common/copy-field";
import { CopyField } from "@/components/common/copy-field";
// hooks
import { useInstance } from "@/hooks/store";

type Props = {
  config: IFormattedInstanceConfiguration;
};

type OidcConfigFormValues = Record<TInstanceOidcAuthenticationConfigurationKeys, string>;

const OIDC_FORM_SWITCH_FIELD: TControllerSwitchFormField<OidcConfigFormValues> = {
  name: "ENABLE_OIDC_SYNC",
  label: "Sync profile on every login",
};

export function InstanceOidcConfigForm(props: Props) {
  const { config } = props;
  // states
  const [isDiscardChangesModalOpen, setIsDiscardChangesModalOpen] = useState(false);
  // store hooks
  const { updateInstanceConfigurations } = useInstance();
  // form data
  const {
    handleSubmit,
    control,
    reset,
    formState: { errors, isDirty, isSubmitting },
  } = useForm<OidcConfigFormValues>({
    defaultValues: {
      OIDC_ISSUER: config["OIDC_ISSUER"],
      OIDC_CLIENT_ID: config["OIDC_CLIENT_ID"],
      OIDC_CLIENT_SECRET: config["OIDC_CLIENT_SECRET"],
      OIDC_DISPLAY_NAME: config["OIDC_DISPLAY_NAME"] || "SSO",
      ENABLE_OIDC_SYNC: config["ENABLE_OIDC_SYNC"] || "0",
      OIDC_GROUPS_CLAIM: config["OIDC_GROUPS_CLAIM"] || "groups",
      ENABLE_OIDC_ROLE_SYNC: config["ENABLE_OIDC_ROLE_SYNC"] || "0",
      OIDC_GROUP_ROLE_MAPPING: config["OIDC_GROUP_ROLE_MAPPING"] || "[]",
    },
  });

  const originURL = !isEmpty(API_BASE_URL) ? API_BASE_URL : typeof window !== "undefined" ? window.location.origin : "";

  const OIDC_FORM_FIELDS: TControllerInputFormField[] = [
    {
      key: "OIDC_ISSUER",
      type: "text",
      label: "Issuer URL",
      description: (
        <>
          The base URL of your identity provider. Plane discovers the rest of the endpoints from{" "}
          <CodeBlock darkerShade>{"{issuer}/.well-known/openid-configuration"}</CodeBlock>.
        </>
      ),
      placeholder: "https://idp.example.com/realms/plane",
      error: Boolean(errors.OIDC_ISSUER),
      required: true,
    },
    {
      key: "OIDC_CLIENT_ID",
      type: "text",
      label: "Client ID",
      description: <>The client/application ID registered with your identity provider.</>,
      placeholder: "plane-client",
      error: Boolean(errors.OIDC_CLIENT_ID),
      required: true,
    },
    {
      key: "OIDC_CLIENT_SECRET",
      type: "password",
      label: "Client secret",
      description: <>The client secret issued alongside the client ID.</>,
      placeholder: "9b0050f94ec1b744e32ce79ea4ffacd40d4119cb",
      error: Boolean(errors.OIDC_CLIENT_SECRET),
      required: true,
    },
    {
      key: "OIDC_DISPLAY_NAME",
      type: "text",
      label: "Display name",
      description: <>Shown on the login button, e.g. &quot;Continue with {"{Display name}"}&quot;.</>,
      placeholder: "SSO",
      error: Boolean(errors.OIDC_DISPLAY_NAME),
      required: false,
    },
    {
      key: "OIDC_GROUPS_CLAIM",
      type: "text",
      label: "Groups claim",
      description: (
        <>
          Name of the userinfo/ID-token claim holding the user&apos;s groups or roles. Varies by identity provider
          &mdash; check your IdP&apos;s documentation if unsure.
        </>
      ),
      placeholder: "groups",
      error: Boolean(errors.OIDC_GROUPS_CLAIM),
      required: false,
    },
  ];

  const OIDC_SERVICE_FIELD: TCopyField[] = [
    {
      key: "Callback_URI",
      label: "Callback URI",
      url: `${originURL}/auth/oidc/callback/`,
      description: <>We will auto-generate this. Paste this into your identity provider&apos;s redirect URI field.</>,
    },
  ];

  const onSubmit = async (formData: OidcConfigFormValues) => {
    const payload: Partial<OidcConfigFormValues> = { ...formData };

    try {
      const response = await updateInstanceConfigurations(payload);
      setToast({
        type: TOAST_TYPE.SUCCESS,
        title: "Done!",
        message: "Your OIDC authentication is configured. You should test it now.",
      });
      reset({
        OIDC_ISSUER: response.find((item) => item.key === "OIDC_ISSUER")?.value,
        OIDC_CLIENT_ID: response.find((item) => item.key === "OIDC_CLIENT_ID")?.value,
        OIDC_CLIENT_SECRET: response.find((item) => item.key === "OIDC_CLIENT_SECRET")?.value,
        OIDC_DISPLAY_NAME: response.find((item) => item.key === "OIDC_DISPLAY_NAME")?.value,
        ENABLE_OIDC_SYNC: response.find((item) => item.key === "ENABLE_OIDC_SYNC")?.value,
        OIDC_GROUPS_CLAIM: response.find((item) => item.key === "OIDC_GROUPS_CLAIM")?.value,
        ENABLE_OIDC_ROLE_SYNC: response.find((item) => item.key === "ENABLE_OIDC_ROLE_SYNC")?.value,
        OIDC_GROUP_ROLE_MAPPING: response.find((item) => item.key === "OIDC_GROUP_ROLE_MAPPING")?.value,
      });
    } catch (err) {
      console.error(err);
    }
  };

  const handleGoBack = (e: React.MouseEvent<HTMLAnchorElement, MouseEvent>) => {
    if (isDirty) {
      e.preventDefault();
      setIsDiscardChangesModalOpen(true);
    }
  };

  return (
    <>
      <ConfirmDiscardModal
        isOpen={isDiscardChangesModalOpen}
        onDiscardHref="/authentication"
        handleClose={() => setIsDiscardChangesModalOpen(false)}
      />
      <div className="flex flex-col gap-8">
        <div className="grid w-full grid-cols-2 gap-x-12 gap-y-8">
          <div className="col-span-2 flex flex-col gap-y-4 pt-1 md:col-span-1">
            <div className="pt-2.5 text-18 font-medium">Identity provider details for Plane</div>
            {OIDC_FORM_FIELDS.map((field) => (
              <ControllerInput
                key={field.key}
                control={control}
                type={field.type}
                name={field.key}
                label={field.label}
                description={field.description}
                placeholder={field.placeholder}
                error={field.error}
                required={field.required}
              />
            ))}
            <ControllerSwitch control={control} field={OIDC_FORM_SWITCH_FIELD} />

            <div className="pt-4 text-18 font-medium">Map identity provider groups to workspace roles</div>
            <div className="flex items-center justify-between gap-1">
              <h4 className="text-sm text-custom-text-300">Enable group &rarr; workspace role mapping on login</h4>
              <Controller
                control={control}
                name="ENABLE_OIDC_ROLE_SYNC"
                render={({ field: { value, onChange } }) => {
                  const isOn = value === "1";
                  return <ToggleSwitch value={isOn} onChange={() => onChange(isOn ? "0" : "1")} size="sm" />;
                }}
              />
            </div>
            <div className="flex flex-col gap-1">
              <h4 className="text-13 text-tertiary">Group &rarr; role mapping</h4>
              <Controller
                control={control}
                name="OIDC_GROUP_ROLE_MAPPING"
                rules={{
                  validate: (value) => {
                    if (!value) return true;
                    try {
                      const parsed = JSON.parse(value);
                      if (!Array.isArray(parsed)) return "Must be a JSON array.";
                      return true;
                    } catch {
                      return "Must be valid JSON.";
                    }
                  },
                }}
                render={({ field: { value, onChange, ref } }) => (
                  <TextArea
                    id="OIDC_GROUP_ROLE_MAPPING"
                    name="OIDC_GROUP_ROLE_MAPPING"
                    ref={ref}
                    value={value}
                    onChange={onChange}
                    hasError={Boolean(errors.OIDC_GROUP_ROLE_MAPPING)}
                    placeholder={'[{"group": "engineering", "workspace_slug": "acme", "role": "admin"}]'}
                    className="font-mono min-h-24 w-full resize-none text-13"
                  />
                )}
              />
              {errors.OIDC_GROUP_ROLE_MAPPING?.message && (
                <p className="text-11 text-danger-primary">{errors.OIDC_GROUP_ROLE_MAPPING.message}</p>
              )}
              <p className="pt-0.5 text-11 text-tertiary">
                JSON array of <CodeBlock darkerShade>{"{group, workspace_slug, role}"}</CodeBlock> entries (role is one
                of <CodeBlock darkerShade>admin</CodeBlock>, <CodeBlock darkerShade>member</CodeBlock>,{" "}
                <CodeBlock darkerShade>guest</CodeBlock>). A matching group auto-joins the user to that workspace and
                never downgrades a role a human admin already set.
              </p>
            </div>

            <div className="flex flex-col gap-1 pt-4">
              <div className="flex items-center gap-4">
                <Button
                  variant="primary"
                  size="lg"
                  onClick={(e) => void handleSubmit(onSubmit)(e)}
                  loading={isSubmitting}
                  disabled={!isDirty}
                >
                  {isSubmitting ? "Saving" : "Save changes"}
                </Button>
                <Link href="/authentication" className={getButtonStyling("secondary", "lg")} onClick={handleGoBack}>
                  Go back
                </Link>
              </div>
            </div>
          </div>
          <div className="col-span-2 md:col-span-1">
            <div className="flex flex-col gap-y-4 rounded-lg bg-layer-1 px-6 pt-1.5 pb-4">
              <div className="pt-2 text-18 font-medium">Plane-provided details for your identity provider</div>
              {OIDC_SERVICE_FIELD.map((field) => (
                <CopyField key={field.key} label={field.label} url={field.url} description={field.description} />
              ))}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
