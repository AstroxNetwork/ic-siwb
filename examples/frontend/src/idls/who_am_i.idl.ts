export const idlFactory = ({ IDL }: any) => {
    return IDL.Service({
        'whoAmI': IDL.Func([], [IDL.Principal], []),
    });
};
export const init = ({ IDL }: any) => { return []; };
