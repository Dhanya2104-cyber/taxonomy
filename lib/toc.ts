// @ts-nocheck
// TODO: Fix this when we turn strict mode on.

import { toc } from "mdast-util-toc"
import { remark } from "remark"
import { visit } from "unist-util-visit"

const textTypes = ["text", "emphasis", "strong", "inlineCode"]

function flattenNode(node) {
  const p = []
  visit(node, (node) => {
    if (!textTypes.includes(node.type)) return
    p.push(node.value)
  })
  return p.join(``)
}

interface Item {
  title: string
  url: string
  items?: Item[]
}

interface Items {
  items?: Item[]
}

function getItems(node, current): Items {
  if (!node) {
    return {}
  }

  if (node.type === "paragraph") {
    visit(node, (item) => {
      if (item.type === "link") {
        current.url = item.url
        current.title = flattenNode(node)
      }

      if (item.type === "text") {
        current.title = flattenNode(node)
      }
    })

    return current
  }

  if (node.type === "list") {
    current.items = node.children.map((i) => getItems(i, {}))

    return current
  } else if (node.type === "listItem") {
    const heading = getItems(node.children[0], {})

    if (node.children.length > 1) {
      getItems(node.children[1], heading)
    }

    return heading
  }

  return {}
}

function sanitizeTableMap(obj: any): any {
  if (!obj || typeof obj !== 'object') return obj
  return JSON.parse(JSON.stringify(obj))
}

function isValidTableMap(obj: any): boolean {
  return Boolean(obj && typeof obj === 'object')
}

const getToc = () => (node, file) => {
  const table = toc(node)
  if (table.map && typeof table.map === 'object') {
    // SECURITY: sanitize table.map before processing
    const sanitizedMap = sanitizeTableMap(table.map);
    if (!isValidTableMap(sanitizedMap)) {
      throw new Error('Invalid sanitized table.map structure');
    }
    file.data = getItems(sanitizedMap, {})
  } else {
    throw new Error('Invalid table.map structure')
  }
}

export type TableOfContents = Items

const sanitizedContent = DOMPurify.sanitize(content)
const result = await remark().use(getToc).process(sanitizedContent)
export async function getTableOfContents(
  content: string
): Promise<TableOfContents> {
  const result = await remark().use(getToc).process(content)

  return result.data
}
