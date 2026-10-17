// SPDX-License-Identifier: MIT
// Copyright (c) 2019 Sherlock Project. Full license: licenses/sherlock.txt.
// Selected name, url and regexCheck fields from sherlock_project/resources/data.json
// at e40a45ec2a074b90703b3b4b842c8a3adbd6ada3. No detection engine is bundled.
export const profileTemplates = [
  {
    name: "GitHub",
    url: "https://www.github.com/{}",
    regex: "^[a-zA-Z0-9](?:[a-zA-Z0-9]|-(?=[a-zA-Z0-9])){0,38}$",
  },
  { name: "GitLab", url: "https://gitlab.com/{}", regex: null },
  { name: "Reddit", url: "https://www.reddit.com/user/{}", regex: null },
  { name: "Keybase", url: "https://keybase.io/{}", regex: null },
  {
    name: "HackerNews",
    url: "https://news.ycombinator.com/user?id={}",
    regex: null,
  },
  {
    name: "DEV Community",
    url: "https://dev.to/{}",
    regex: "^[a-zA-Z][a-zA-Z0-9_-]*$",
  },
  { name: "npm", url: "https://www.npmjs.com/~{}", regex: null },
  { name: "Codeberg", url: "https://codeberg.org/{}", regex: null },
  { name: "PyPI", url: "https://pypi.org/user/{}", regex: null },
];
