chrome.action.onClicked.addListener(async tab => {
  if (!tab.id || !/^https?:\/\//.test(tab.url || '')) return;
  const key = crypto.randomUUID();
  const records = await chrome.storage.session.get(null);
  const old = Object.keys(records).filter(name => name.startsWith('target_'));
  if (old.length >= 100) await chrome.storage.session.remove(old.slice(0, old.length - 99));
  await chrome.storage.session.set({ [`target_${key}`]: { tabId: tab.id, url: tab.url } });
  await chrome.tabs.create({ url: chrome.runtime.getURL(`collector.html?session=${key}`) });
});
