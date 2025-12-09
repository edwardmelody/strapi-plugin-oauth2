declare const routes: {
    'content-api': {
        type: string;
        routes: {
            method: string;
            path: string;
            handler: string;
            config: {
                policies: any[];
                middlewares: any[];
            };
        }[];
    };
    admin: {
        type: string;
        routes: {
            method: string;
            path: string;
            handler: string;
            config: {
                policies: {
                    name: string;
                    config: {
                        actions: string[];
                    };
                }[];
            };
        }[];
    };
};
export default routes;
