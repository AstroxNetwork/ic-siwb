import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';
export interface _SERVICE {
    'whoAmI': ActorMethod<[], Principal>,
}
export declare const idlFactory: IDL.InterfaceFactory;
