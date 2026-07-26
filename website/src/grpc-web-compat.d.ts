import 'grpc-web';

declare module 'grpc-web' {
  interface Error extends globalThis.Error {}
}
