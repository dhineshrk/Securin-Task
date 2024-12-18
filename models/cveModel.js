const mongoose = require('mongoose');

const cveSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  publishedDate: { type: String },
  lastModifiedDate: { type: String },
  descriptions: [{ value: String }],
});

cveSchema.index({ id: 1 });
cveSchema.index({ publishedDate: 1 });

module.exports = mongoose.model('CVE', cveSchema);
