// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useRpcClient } from '@mysten/core';
import {
    is,
    SuiObject,
    type GetObjectDataResponse,
    normalizeSuiAddress,
    type MoveSuiSystemObjectFields,
} from '@mysten/sui.js';
import { useQuery, type UseQueryResult } from '@tanstack/react-query';

export function useGetSystemObject() {
    // TODO: Replace with `sui_getSuiSystemState` once it's supported:
    const { data, ...query } = useGetObject('0x5');

    const systemObject =
        data &&
        is(data.details, SuiObject) &&
        data.details.data.dataType === 'moveObject'
            ? (data.details.data.fields as MoveSuiSystemObjectFields)
            : null;

    return {
        ...query,
        data: systemObject,
    };
}

export function useGetObject(
    objectId: string
): UseQueryResult<GetObjectDataResponse, unknown> {
    const rpc = useRpcClient();
    const normalizedObjId = normalizeSuiAddress(objectId);
    const response = useQuery(
        ['object', normalizedObjId],
        async () => rpc.getObject(normalizedObjId),
        { enabled: !!objectId }
    );

    return response;
}
