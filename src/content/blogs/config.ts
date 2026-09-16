import { defineCollection, z } from 'astro:content';

const blogCollection = defineCollection({
  schema: z.object({
    title: z.string(),
    description: z.string().optional(),
    pubDate: z.string(),
    category: z.enum(['random-tech', 'cyber', 'certs']),
  }),
});

export const collections = {
  blogs: blogCollection,
};
