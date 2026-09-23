// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
import React from 'react';

type Props = { name: string };

export function Greeting({ name }: Props) {
  return <p className="greeting">{formatName(name)}</p>;
}

export const Panel = (props: Props) => {
  const label = props.name.trim();
  return <Greeting name={label} />;
};
