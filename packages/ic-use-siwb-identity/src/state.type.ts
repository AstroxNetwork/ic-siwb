import type { DelegationChain, DelegationIdentity } from '@dfinity/identity';

import type { ActorSubclass } from '@dfinity/agent';
import type { SIWB_IDENTITY_SERVICE } from './service.interface';

export type PrepareLoginStatus = 'error' | 'preparing' | 'success' | 'idle';
export type LoginStatus = 'error' | 'logging-in' | 'success' | 'idle';

export type State = {
  anonymousActor?: ActorSubclass<SIWB_IDENTITY_SERVICE>;
  isInitializing: boolean;
  prepareLoginStatus: PrepareLoginStatus;
  prepareLoginError?: Error;
  siwbMessage?: string;
  loginStatus: LoginStatus;
  loginError?: Error;
  identity?: DelegationIdentity;
  identityAddress?: string;
  delegationChain?: DelegationChain;
};