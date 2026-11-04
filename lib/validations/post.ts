import * as z from "zod"

export const postPatchSchema = z.object({
  title: z.string().min(3).max(128).optional(),

  // TODO: Type this properly from editorjs block types?
  content: z.record(z.object({ type: z.string(), data: z.object({ key: z.string(), value: z.string() }) })).optional(),
})
