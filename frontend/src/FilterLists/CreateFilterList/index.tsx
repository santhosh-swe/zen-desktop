import { Button, FormGroup, InputGroup, Tooltip } from '@blueprintjs/core';
import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { AppToaster } from '@/common/toaster';
import { useProxyState } from '@/context/ProxyStateContext';
import { FilterListType } from '@/FilterLists/types';
import { AddFilterList } from 'wails/go/config/Config';

export function CreateFilterList({ onAdd }: { onAdd: () => void }) {
  const { t } = useTranslation();
  const { isProxyRunning } = useProxyState();
  const urlRef = useRef<HTMLInputElement>(null);
  const nameRef = useRef<HTMLInputElement>(null);

  const [loading, setLoading] = useState(false);

  return (
    <div className="filter-lists__create-filter-list">
      <FormGroup label="URL" labelFor="url" labelInfo="(required)">
        <InputGroup id="url" placeholder="https://example.com/filter-list.txt" required type="url" inputRef={urlRef} />
      </FormGroup>

      <FormGroup label="Name" labelFor="name" labelInfo="(optional)">
        <InputGroup id="name" placeholder="Example filter list" type="text" inputRef={nameRef} />
      </FormGroup>

      <Tooltip content={t('common.stopProxyToAddFilter') as string} disabled={!isProxyRunning} placement="top">
        <Button
          icon="add"
          intent="primary"
          fill
          disabled={isProxyRunning}
          onClick={async () => {
            if (!urlRef.current?.checkValidity()) {
              urlRef.current?.focus();
              return;
            }
            const url = urlRef.current?.value;
            const name = nameRef.current?.value || url;

            setLoading(true);
            try {
              await AddFilterList({
                url,
                name,
                type: FilterListType.CUSTOM,
                enabled: true,
                // Hardened build: remote lists can never be marked as trusted.
                trusted: false,
                locales: [], // FIX: this is a dirty fix, rewrite by making AddFilterList accept a custom struct.
              });
            } catch (err) {
              AppToaster.show({
                message: t('createFilterList.addError', { error: String(err) }),
                intent: 'danger',
              });
            }
            setLoading(false);
            if (urlRef.current) urlRef.current.value = '';
            if (nameRef.current) nameRef.current.value = '';
            onAdd();
          }}
          loading={loading}
        >
          {t('createFilterList.addList')}
        </Button>
      </Tooltip>
    </div>
  );
}
