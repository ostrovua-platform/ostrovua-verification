'use strict';

const sharp = require('sharp');
const {
  classifyUpload,
  decodeBase64Strict,
} = require('./security_policy');

const RASTER_MIMES = new Set([
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'image/heic',
  'image/avif',
]);
const DEFAULT_MAX_PIXELS = 40_000_000;
const DEFAULT_MAX_TOTAL_PIXELS = 120_000_000;
const DEFAULT_MAX_FRAMES = 120;

sharp.cache({ memory: 0, files: 0, items: 0 });

class MediaSanitizationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'MediaSanitizationError';
    this.code = code;
  }
}

function validateRasterMetadata(metadata, {
  maximumFrames,
  maximumTotalPixels,
}) {
  const width = Number(metadata?.width);
  const height = Number(metadata?.pageHeight || metadata?.height);
  const frames = Number(metadata?.pages || 1);
  if (!Number.isSafeInteger(width) || width < 1 ||
      !Number.isSafeInteger(height) || height < 1 ||
      !Number.isSafeInteger(frames) || frames < 1) {
    throw new MediaSanitizationError('media_decode_failed', 'Invalid image geometry');
  }
  if (frames > maximumFrames || width * height * frames > maximumTotalPixels) {
    throw new MediaSanitizationError('media_too_complex', 'Image exceeds decoding limits');
  }
}

function assertMetadataRemoved(metadata) {
  if (metadata?.exif || metadata?.xmp || metadata?.iptc || metadata?.icc) {
    throw new MediaSanitizationError(
      'media_metadata_retained',
      'Sanitized image unexpectedly contains metadata'
    );
  }
}

async function sanitizeRasterImage(input, {
  maximumInputBytes = 25 * 1024 * 1024,
  maximumOutputBytes = 25 * 1024 * 1024,
  maximumPixels = DEFAULT_MAX_PIXELS,
  maximumTotalPixels = DEFAULT_MAX_TOTAL_PIXELS,
  maximumFrames = DEFAULT_MAX_FRAMES,
  maximumDimension,
} = {}) {
  if (!Buffer.isBuffer(input) || input.length < 1) {
    throw new MediaSanitizationError('media_invalid', 'Image bytes are required');
  }
  if (input.length > maximumInputBytes) {
    throw new MediaSanitizationError('media_too_large', 'Image exceeds input limit');
  }

  const detected = classifyUpload(input);
  if (!detected || !RASTER_MIMES.has(detected.mime)) {
    throw new MediaSanitizationError(
      'media_unsupported',
      'Only decodable raster images may be stored'
    );
  }

  let metadata;
  try {
    metadata = await sharp(input, {
      animated: true,
      failOn: 'error',
      limitInputPixels: maximumPixels,
      sequentialRead: true,
    }).metadata();
  } catch (error) {
    throw new MediaSanitizationError('media_decode_failed', error.message);
  }
  validateRasterMetadata(metadata, { maximumFrames, maximumTotalPixels });

  let pipeline = sharp(input, {
    animated: true,
    failOn: 'error',
    limitInputPixels: maximumPixels,
    sequentialRead: true,
  }).rotate();
  if (Number.isSafeInteger(maximumDimension) && maximumDimension > 0) {
    pipeline = pipeline.resize({
      width: maximumDimension,
      height: maximumDimension,
      fit: 'inside',
      withoutEnlargement: true,
    });
  }

  let output;
  try {
    output = await pipeline
      // Rebuild from decoded pixels. Because withMetadata() is never called,
      // EXIF/GPS, XMP, IPTC, ICC, capture time and device fields are dropped.
      .webp({
        quality: 85,
        alphaQuality: 90,
        effort: 4,
        smartSubsample: true,
      })
      .toBuffer();
  } catch (error) {
    throw new MediaSanitizationError('media_encode_failed', error.message);
  }

  if (output.length < 1 || output.length > maximumOutputBytes) {
    output.fill(0);
    throw new MediaSanitizationError('media_too_large', 'Sanitized image exceeds output limit');
  }

  try {
    const sanitizedMetadata = await sharp(output, {
      animated: true,
      failOn: 'error',
      limitInputPixels: maximumPixels,
    }).metadata();
    validateRasterMetadata(sanitizedMetadata, { maximumFrames, maximumTotalPixels });
    assertMetadataRemoved(sanitizedMetadata);
  } catch (error) {
    output.fill(0);
    if (error instanceof MediaSanitizationError) throw error;
    throw new MediaSanitizationError('media_output_invalid', error.message);
  }

  return {
    buffer: output,
    extension: 'webp',
    mime: 'image/webp',
    disposition: 'inline',
  };
}

async function sanitizeAvatarDataUrl(value, {
  maximumInputBytes = 2 * 1024 * 1024,
  maximumOutputBytes = 2 * 1024 * 1024,
  maximumDimension = 1024,
} = {}) {
  if (typeof value !== 'string') return null;
  const match = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/]*={0,2})$/.exec(value);
  if (!match) return null;

  const decoded = decodeBase64Strict(match[2]);
  if (!decoded || decoded.length < 1 || decoded.length > maximumInputBytes) {
    if (decoded) decoded.fill(0);
    return null;
  }

  let sanitized;
  try {
    const detected = classifyUpload(decoded);
    if (!detected || detected.mime !== match[1]) return null;
    sanitized = await sanitizeRasterImage(decoded, {
      maximumInputBytes,
      maximumOutputBytes,
      maximumDimension,
    });
    return `data:${sanitized.mime};base64,${sanitized.buffer.toString('base64')}`;
  } catch (error) {
    if (error instanceof MediaSanitizationError) return null;
    throw error;
  } finally {
    decoded.fill(0);
    if (sanitized?.buffer) sanitized.buffer.fill(0);
  }
}

module.exports = {
  MediaSanitizationError,
  sanitizeAvatarDataUrl,
  sanitizeRasterImage,
};
