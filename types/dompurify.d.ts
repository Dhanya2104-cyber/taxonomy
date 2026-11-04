declare module "dompurify" {
  const sanitize: (html: string) => string
  export default { sanitize }
}
