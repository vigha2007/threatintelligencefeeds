function isUnsafeProperty(key) {
  return key === "__proto__";
}
function isDeepKey(key) {
  switch (typeof key) {
    case "number":
    case "symbol":
      return false;
    case "string":
      return key.includes(".") || key.includes("[") || key.includes("]");
  }
}
function toKey(value) {
  if (typeof value === "string" || typeof value === "symbol") return value;
  if (Object.is(value?.valueOf?.(), -0)) return "-0";
  return String(value);
}
function toString(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(toString).join(",");
  const result = String(value);
  if (result === "0" && Object.is(Number(value), -0)) return "-0";
  return result;
}
function toPath(deepKey) {
  if (Array.isArray(deepKey)) return deepKey.map(toKey);
  if (typeof deepKey === "symbol") return [deepKey];
  deepKey = toString(deepKey);
  const result = [];
  const length = deepKey.length;
  if (length === 0) return result;
  let index = 0;
  let key = "";
  let quoteChar = "";
  let bracket = false;
  if (deepKey.charCodeAt(0) === 46) {
    result.push("");
    index++;
  }
  while (index < length) {
    const char = deepKey[index];
    if (quoteChar) if (char === "\\" && index + 1 < length) {
      index++;
      key += deepKey[index];
    } else if (char === quoteChar) quoteChar = "";
    else key += char;
    else if (bracket) if (char === '"' || char === "'") quoteChar = char;
    else if (char === "]") {
      bracket = false;
      result.push(key);
      key = "";
    } else key += char;
    else if (char === "[") {
      bracket = true;
      if (key) {
        result.push(key);
        key = "";
      }
    } else if (char === ".") {
      if (key) {
        result.push(key);
        key = "";
      }
    } else key += char;
    index++;
  }
  if (key) result.push(key);
  return result;
}
function get(object, path, defaultValue) {
  if (object == null) return defaultValue;
  switch (typeof path) {
    case "string": {
      if (isUnsafeProperty(path)) return defaultValue;
      const result = object[path];
      if (result === void 0) if (isDeepKey(path)) return get(object, toPath(path), defaultValue);
      else return defaultValue;
      return result;
    }
    case "number":
    case "symbol": {
      if (typeof path === "number") path = toKey(path);
      const result = object[path];
      if (result === void 0) return defaultValue;
      return result;
    }
    default: {
      if (Array.isArray(path)) return getWithPath(object, path, defaultValue);
      if (Object.is(path?.valueOf(), -0)) path = "-0";
      else path = String(path);
      if (isUnsafeProperty(path)) return defaultValue;
      const result = object[path];
      if (result === void 0) return defaultValue;
      return result;
    }
  }
}
function getWithPath(object, path, defaultValue) {
  if (path.length === 0) return defaultValue;
  let current = object;
  for (let index = 0; index < path.length; index++) {
    if (current == null) return defaultValue;
    if (isUnsafeProperty(path[index])) return defaultValue;
    current = current[path[index]];
  }
  if (current === void 0) return defaultValue;
  return current;
}
function uniqBy$1(arr, mapper) {
  const map = /* @__PURE__ */ new Map();
  for (let i = 0; i < arr.length; i++) {
    const item = arr[i];
    const key = mapper(item, i, arr);
    if (!map.has(key)) map.set(key, item);
  }
  return Array.from(map.values());
}
function ary(func, n) {
  return function(...args) {
    return func.apply(this, args.slice(0, n));
  };
}
function identity(x) {
  return x;
}
function property(path) {
  return function(object) {
    return get(object, path);
  };
}
function isPrimitive(value) {
  return value == null || typeof value !== "object" && typeof value !== "function";
}
function isTypedArray(x) {
  return ArrayBuffer.isView(x) && !(x instanceof DataView);
}
function getSymbols(object) {
  return Object.getOwnPropertySymbols(object).filter((symbol) => Object.prototype.propertyIsEnumerable.call(object, symbol));
}
function getTag(value) {
  if (value == null) return value === void 0 ? "[object Undefined]" : "[object Null]";
  return Object.prototype.toString.call(value);
}
const regexpTag = "[object RegExp]";
const stringTag = "[object String]";
const numberTag = "[object Number]";
const booleanTag = "[object Boolean]";
const argumentsTag = "[object Arguments]";
const symbolTag = "[object Symbol]";
const dateTag = "[object Date]";
const mapTag = "[object Map]";
const setTag = "[object Set]";
const arrayTag = "[object Array]";
const arrayBufferTag = "[object ArrayBuffer]";
const objectTag = "[object Object]";
const dataViewTag = "[object DataView]";
const uint8ArrayTag = "[object Uint8Array]";
const uint8ClampedArrayTag = "[object Uint8ClampedArray]";
const uint16ArrayTag = "[object Uint16Array]";
const uint32ArrayTag = "[object Uint32Array]";
const int8ArrayTag = "[object Int8Array]";
const int16ArrayTag = "[object Int16Array]";
const int32ArrayTag = "[object Int32Array]";
const float32ArrayTag = "[object Float32Array]";
const float64ArrayTag = "[object Float64Array]";
const globalThis_ = typeof globalThis === "object" && globalThis || typeof window === "object" && window || typeof self === "object" && self || typeof global === "object" && global || /* @__PURE__ */ (function() {
  return this;
})();
function isBuffer(x) {
  return typeof globalThis_.Buffer !== "undefined" && globalThis_.Buffer.isBuffer(x);
}
function cloneDeepWith$1(obj, cloneValue) {
  return cloneDeepWithImpl(obj, void 0, obj, /* @__PURE__ */ new Map(), cloneValue);
}
function cloneDeepWithImpl(valueToClone, keyToClone, objectToClone, stack = /* @__PURE__ */ new Map(), cloneValue = void 0) {
  const cloned = cloneValue?.(valueToClone, keyToClone, objectToClone, stack);
  if (cloned !== void 0) return cloned;
  if (isPrimitive(valueToClone)) return valueToClone;
  if (stack.has(valueToClone)) return stack.get(valueToClone);
  if (Array.isArray(valueToClone)) {
    const result = new Array(valueToClone.length);
    stack.set(valueToClone, result);
    for (let i = 0; i < valueToClone.length; i++) result[i] = cloneDeepWithImpl(valueToClone[i], i, objectToClone, stack, cloneValue);
    if (Object.hasOwn(valueToClone, "index")) result.index = valueToClone.index;
    if (Object.hasOwn(valueToClone, "input")) result.input = valueToClone.input;
    return result;
  }
  if (valueToClone instanceof Date) return new Date(valueToClone.getTime());
  if (valueToClone instanceof RegExp) {
    const result = new RegExp(valueToClone.source, valueToClone.flags);
    result.lastIndex = valueToClone.lastIndex;
    return result;
  }
  if (valueToClone instanceof Map) {
    const result = /* @__PURE__ */ new Map();
    stack.set(valueToClone, result);
    for (const [key, value] of valueToClone) result.set(key, cloneDeepWithImpl(value, key, objectToClone, stack, cloneValue));
    return result;
  }
  if (valueToClone instanceof Set) {
    const result = /* @__PURE__ */ new Set();
    stack.set(valueToClone, result);
    for (const value of valueToClone) result.add(cloneDeepWithImpl(value, void 0, objectToClone, stack, cloneValue));
    return result;
  }
  if (isBuffer(valueToClone)) return valueToClone.subarray();
  if (isTypedArray(valueToClone)) {
    const result = new (Object.getPrototypeOf(valueToClone)).constructor(valueToClone.length);
    stack.set(valueToClone, result);
    for (let i = 0; i < valueToClone.length; i++) result[i] = cloneDeepWithImpl(valueToClone[i], i, objectToClone, stack, cloneValue);
    return result;
  }
  if (valueToClone instanceof ArrayBuffer || typeof SharedArrayBuffer !== "undefined" && valueToClone instanceof SharedArrayBuffer) return valueToClone.slice(0);
  if (valueToClone instanceof DataView) {
    const result = new DataView(valueToClone.buffer.slice(0), valueToClone.byteOffset, valueToClone.byteLength);
    stack.set(valueToClone, result);
    copyProperties(result, valueToClone, objectToClone, stack, cloneValue);
    return result;
  }
  if (typeof File !== "undefined" && valueToClone instanceof File) {
    const result = new File([valueToClone], valueToClone.name, { type: valueToClone.type });
    stack.set(valueToClone, result);
    copyProperties(result, valueToClone, objectToClone, stack, cloneValue);
    return result;
  }
  if (typeof Blob !== "undefined" && valueToClone instanceof Blob) {
    const result = new Blob([valueToClone], { type: valueToClone.type });
    stack.set(valueToClone, result);
    copyProperties(result, valueToClone, objectToClone, stack, cloneValue);
    return result;
  }
  if (valueToClone instanceof Error) {
    const result = structuredClone(valueToClone);
    stack.set(valueToClone, result);
    result.message = valueToClone.message;
    result.name = valueToClone.name;
    result.stack = valueToClone.stack;
    result.cause = valueToClone.cause;
    result.constructor = valueToClone.constructor;
    copyProperties(result, valueToClone, objectToClone, stack, cloneValue);
    return result;
  }
  if (valueToClone instanceof Boolean) {
    const result = new Boolean(valueToClone.valueOf());
    stack.set(valueToClone, result);
    copyProperties(result, valueToClone, objectToClone, stack, cloneValue);
    return result;
  }
  if (valueToClone instanceof Number) {
    const result = new Number(valueToClone.valueOf());
    stack.set(valueToClone, result);
    copyProperties(result, valueToClone, objectToClone, stack, cloneValue);
    return result;
  }
  if (valueToClone instanceof String) {
    const result = new String(valueToClone.valueOf());
    stack.set(valueToClone, result);
    copyProperties(result, valueToClone, objectToClone, stack, cloneValue);
    return result;
  }
  if (typeof valueToClone === "object" && isCloneableObject(valueToClone)) {
    const result = Object.create(Object.getPrototypeOf(valueToClone));
    stack.set(valueToClone, result);
    copyProperties(result, valueToClone, objectToClone, stack, cloneValue);
    return result;
  }
  return valueToClone;
}
function copyProperties(target, source, objectToClone = target, stack, cloneValue) {
  const keys = [...Object.keys(source), ...getSymbols(source)];
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    const descriptor = Object.getOwnPropertyDescriptor(target, key);
    if (descriptor == null || descriptor.writable) target[key] = cloneDeepWithImpl(source[key], key, objectToClone, stack, cloneValue);
  }
}
function isCloneableObject(object) {
  switch (getTag(object)) {
    case argumentsTag:
    case arrayTag:
    case arrayBufferTag:
    case dataViewTag:
    case booleanTag:
    case dateTag:
    case float32ArrayTag:
    case float64ArrayTag:
    case int8ArrayTag:
    case int16ArrayTag:
    case int32ArrayTag:
    case mapTag:
    case numberTag:
    case objectTag:
    case regexpTag:
    case setTag:
    case stringTag:
    case symbolTag:
    case uint8ArrayTag:
    case uint8ClampedArrayTag:
    case uint16ArrayTag:
    case uint32ArrayTag:
      return true;
    default:
      return false;
  }
}
function cloneDeep$1(obj) {
  return cloneDeepWithImpl(obj, void 0, obj, /* @__PURE__ */ new Map(), void 0);
}
function isEqualsSameValueZero(value, other) {
  return value === other || Number.isNaN(value) && Number.isNaN(other);
}
function isObject(value) {
  return value !== null && (typeof value === "object" || typeof value === "function");
}
function isMatchWith(target, source, compare) {
  if (typeof compare !== "function") return isMatchWith(target, source, () => void 0);
  return isMatchWithInternal(target, source, function doesMatch(objValue, srcValue, key, object, source2, stack) {
    const isEqual = compare(objValue, srcValue, key, object, source2, stack);
    if (isEqual !== void 0) return Boolean(isEqual);
    return isMatchWithInternal(objValue, srcValue, doesMatch, stack);
  }, /* @__PURE__ */ new Map());
}
function isMatchWithInternal(target, source, compare, stack) {
  if (source === target) return true;
  switch (typeof source) {
    case "object":
      return isObjectMatch(target, source, compare, stack);
    case "function":
      if (Object.keys(source).length > 0) return isMatchWithInternal(target, { ...source }, compare, stack);
      return isEqualsSameValueZero(target, source);
    default:
      if (!isObject(target)) return isEqualsSameValueZero(target, source);
      if (typeof source === "string") return source === "";
      return true;
  }
}
function isObjectMatch(target, source, compare, stack) {
  if (source == null) return true;
  if (Array.isArray(source)) return isArrayMatch(target, source, compare, stack);
  if (source instanceof Map) return isMapMatch(target, source, compare, stack);
  if (source instanceof Set) return isSetMatch(target, source, compare, stack);
  const keys = Object.keys(source);
  if (target == null || isPrimitive(target)) return keys.length === 0;
  if (keys.length === 0) return true;
  if (stack?.has(source)) return stack.get(source) === target;
  stack?.set(source, target);
  try {
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      if (!isPrimitive(target) && !(key in target)) return false;
      if (source[key] === void 0 && target[key] !== void 0) return false;
      if (source[key] === null && target[key] !== null) return false;
      if (!compare(target[key], source[key], key, target, source, stack)) return false;
    }
    return true;
  } finally {
    stack?.delete(source);
  }
}
function isMapMatch(target, source, compare, stack) {
  if (source.size === 0) return true;
  if (!(target instanceof Map)) return false;
  for (const [key, sourceValue] of source.entries()) if (compare(target.get(key), sourceValue, key, target, source, stack) === false) return false;
  return true;
}
function isArrayMatch(target, source, compare, stack) {
  if (source.length === 0) return true;
  if (!Array.isArray(target)) return false;
  const countedIndex = /* @__PURE__ */ new Set();
  for (let i = 0; i < source.length; i++) {
    const sourceItem = source[i];
    let found = false;
    for (let j = 0; j < target.length; j++) {
      if (countedIndex.has(j)) continue;
      const targetItem = target[j];
      let matches2 = false;
      if (compare(targetItem, sourceItem, i, target, source, stack)) matches2 = true;
      if (matches2) {
        countedIndex.add(j);
        found = true;
        break;
      }
    }
    if (!found) return false;
  }
  return true;
}
function isSetMatch(target, source, compare, stack) {
  if (source.size === 0) return true;
  if (!(target instanceof Set)) return false;
  return isArrayMatch([...target], [...source], compare, stack);
}
function isMatch(target, source) {
  return isMatchWith(target, source, () => void 0);
}
function matches(source) {
  source = cloneDeep$1(source);
  return (target) => {
    return isMatch(target, source);
  };
}
function cloneDeepWith(obj, customizer) {
  return cloneDeepWith$1(obj, (value, key, object, stack) => {
    if (typeof obj !== "object") return;
    if (getTag(obj) === "[object Object]" && typeof obj.constructor !== "function") {
      const result = {};
      stack.set(obj, result);
      copyProperties(result, obj, object, stack);
      return result;
    }
    switch (Object.prototype.toString.call(obj)) {
      case numberTag:
      case stringTag:
      case booleanTag: {
        const result = new obj.constructor(obj?.valueOf());
        copyProperties(result, obj);
        return result;
      }
      case argumentsTag: {
        const result = {};
        copyProperties(result, obj);
        result.length = obj.length;
        result[Symbol.iterator] = obj[Symbol.iterator];
        return result;
      }
      default:
        return;
    }
  });
}
function cloneDeep(obj) {
  return cloneDeepWith(obj);
}
const IS_UNSIGNED_INTEGER = /^(?:0|[1-9]\d*)$/;
function isIndex(value, length = Number.MAX_SAFE_INTEGER) {
  switch (typeof value) {
    case "number":
      return Number.isInteger(value) && value >= 0 && value < length;
    case "symbol":
      return false;
    case "string":
      return IS_UNSIGNED_INTEGER.test(value);
  }
}
function isArguments(value) {
  return value !== null && typeof value === "object" && getTag(value) === "[object Arguments]";
}
function has(object, path) {
  let resolvedPath;
  if (Array.isArray(path)) resolvedPath = path;
  else if (typeof path === "string" && isDeepKey(path) && object?.[path] == null) resolvedPath = toPath(path);
  else resolvedPath = [path];
  if (resolvedPath.length === 0) return false;
  let current = object;
  for (let i = 0; i < resolvedPath.length; i++) {
    const key = resolvedPath[i];
    if (current == null || !Object.hasOwn(current, key)) {
      if (!((Array.isArray(current) || isArguments(current)) && isIndex(key) && key < current.length)) return false;
    }
    current = current[key];
  }
  return true;
}
function matchesProperty(property2, source) {
  switch (typeof property2) {
    case "object":
      if (Object.is(property2?.valueOf(), -0)) property2 = "-0";
      break;
    case "number":
      property2 = toKey(property2);
      break;
  }
  source = cloneDeep(source);
  return function(target) {
    const result = get(target, property2);
    if (result === void 0) return has(target, property2);
    if (source === void 0) return result === void 0;
    return isMatch(result, source);
  };
}
function iteratee(value) {
  if (value == null) return identity;
  switch (typeof value) {
    case "function":
      return value;
    case "object":
      if (Array.isArray(value) && value.length === 2) return matchesProperty(value[0], value[1]);
      return matches(value);
    case "string":
    case "symbol":
    case "number":
      return property(value);
  }
}
function isLength(value) {
  return Number.isSafeInteger(value) && value >= 0;
}
function isArrayLike(value) {
  return value != null && typeof value !== "function" && isLength(value.length);
}
function isObjectLike(value) {
  return typeof value === "object" && value !== null;
}
function isArrayLikeObject(value) {
  return isObjectLike(value) && isArrayLike(value);
}
function uniqBy(array, iteratee$1 = identity) {
  if (!isArrayLikeObject(array)) return [];
  return uniqBy$1(Array.from(array), ary(iteratee(iteratee$1), 1));
}
function flatten(arr, depth = 1) {
  const result = [];
  const flooredDepth = Math.floor(depth);
  const recursive = (arr2, currentDepth) => {
    for (let i = 0; i < arr2.length; i++) {
      const item = arr2[i];
      if (Array.isArray(item) && currentDepth < flooredDepth) recursive(item, currentDepth + 1);
      else result.push(item);
    }
  };
  recursive(arr, 0);
  return result;
}
function isIterateeCall(value, index, object) {
  if (!isObject(object)) return false;
  if (typeof index === "number" && isArrayLike(object) && isIndex(index) && index < object.length || typeof index === "string" && index in object) return isEqualsSameValueZero(object[index], value);
  return false;
}
function getPriority(a) {
  if (typeof a === "symbol") return 1;
  if (a === null) return 2;
  if (a === void 0) return 3;
  if (a !== a) return 4;
  return 0;
}
const compareValues = (a, b, order) => {
  if (a !== b) {
    const aPriority = getPriority(a);
    const bPriority = getPriority(b);
    if (aPriority === bPriority && aPriority === 0) {
      if (a < b) return order === "desc" ? 1 : -1;
      if (a > b) return order === "desc" ? -1 : 1;
    }
    return order === "desc" ? bPriority - aPriority : aPriority - bPriority;
  }
  return 0;
};
function isSymbol(value) {
  return typeof value === "symbol" || value instanceof Symbol;
}
const regexIsDeepProp = /\.|\[(?:[^[\]]*|(["'])(?:(?!\1)[^\\]|\\.)*?\1)\]/;
const regexIsPlainProp = /^\w*$/;
function isKey(value, object) {
  if (Array.isArray(value)) return false;
  if (typeof value === "number" || typeof value === "boolean" || value == null || isSymbol(value)) return true;
  return typeof value === "string" && (regexIsPlainProp.test(value) || !regexIsDeepProp.test(value)) || object != null;
}
function orderBy(collection, criteria, orders, guard) {
  if (collection == null) return [];
  orders = orders;
  if (!Array.isArray(collection)) collection = Object.values(collection);
  if (!Array.isArray(criteria)) criteria = criteria == null ? [null] : [criteria];
  if (criteria.length === 0) criteria = [null];
  if (!Array.isArray(orders)) orders = orders == null ? [] : [orders];
  orders = orders.map((order) => String(order));
  const getValueByNestedPath = (object, path) => {
    let target = object;
    for (let i = 0; i < path.length && target != null; ++i) target = target[path[i]];
    return target;
  };
  const getValueByCriterion = (criterion, object) => {
    if (object == null || criterion == null) return object;
    if (typeof criterion === "object" && "key" in criterion) {
      if (Object.hasOwn(object, criterion.key)) return object[criterion.key];
      return getValueByNestedPath(object, criterion.path);
    }
    if (typeof criterion === "function") return criterion(object);
    if (Array.isArray(criterion)) return getValueByNestedPath(object, criterion);
    if (typeof object === "object") return object[criterion];
    return object;
  };
  const preparedCriteria = criteria.map((criterion) => {
    if (Array.isArray(criterion) && criterion.length === 1) criterion = criterion[0];
    if (criterion == null || typeof criterion === "function" || Array.isArray(criterion) || isKey(criterion)) return criterion;
    return {
      key: criterion,
      path: toPath(criterion)
    };
  });
  return collection.map((item) => ({
    original: item,
    criteria: preparedCriteria.map((criterion) => getValueByCriterion(criterion, item))
  })).slice().sort((a, b) => {
    for (let i = 0; i < preparedCriteria.length; i++) {
      const comparedResult = compareValues(a.criteria[i], b.criteria[i], orders[i]);
      if (comparedResult !== 0) return comparedResult;
    }
    return 0;
  }).map((item) => item.original);
}
function sortBy(collection, ...criteria) {
  const length = criteria.length;
  if (length > 1 && isIterateeCall(collection, criteria[0], criteria[1])) criteria = [];
  else if (length > 2 && isIterateeCall(criteria[0], criteria[1], criteria[2])) criteria = [criteria[0]];
  return orderBy(collection, flatten(criteria), ["asc"]);
}
function debounce$1(func, debounceMs, { signal, edges } = {}) {
  let pendingThis = void 0;
  let pendingArgs = null;
  const leading = edges != null && edges.includes("leading");
  const trailing = edges == null || edges.includes("trailing");
  const invoke = () => {
    if (pendingArgs !== null) {
      func.apply(pendingThis, pendingArgs);
      pendingThis = void 0;
      pendingArgs = null;
    }
  };
  const onTimerEnd = () => {
    if (trailing) invoke();
    cancel();
  };
  let timeoutId = null;
  const schedule = () => {
    if (timeoutId != null) clearTimeout(timeoutId);
    timeoutId = setTimeout(() => {
      timeoutId = null;
      onTimerEnd();
    }, debounceMs);
  };
  const cancelTimer = () => {
    if (timeoutId !== null) {
      clearTimeout(timeoutId);
      timeoutId = null;
    }
  };
  const cancel = () => {
    cancelTimer();
    pendingThis = void 0;
    pendingArgs = null;
  };
  const flush = () => {
    invoke();
  };
  const debounced = function(...args) {
    if (signal?.aborted) return;
    pendingThis = this;
    pendingArgs = args;
    const isFirstCall = timeoutId == null;
    schedule();
    if (leading && isFirstCall) invoke();
  };
  debounced.schedule = schedule;
  debounced.cancel = cancel;
  debounced.flush = flush;
  signal?.addEventListener("abort", cancel, { once: true });
  return debounced;
}
function debounce(func, debounceMs = 0, options = {}) {
  if (typeof options !== "object") options = {};
  const { leading = false, trailing = true, maxWait } = options;
  const edges = Array(2);
  if (leading) edges[0] = "leading";
  if (trailing) edges[1] = "trailing";
  let result = void 0;
  let pendingAt = null;
  const _debounced = debounce$1(function(...args) {
    result = func.apply(this, args);
    pendingAt = null;
  }, debounceMs, { edges });
  const debounced = function(...args) {
    if (maxWait != null) {
      if (pendingAt === null) pendingAt = Date.now();
      if (Date.now() - pendingAt >= maxWait) {
        result = func.apply(this, args);
        pendingAt = Date.now();
        _debounced.cancel();
        _debounced.schedule();
        return result;
      }
    }
    _debounced.apply(this, args);
    return result;
  };
  const flush = () => {
    _debounced.flush();
    return result;
  };
  debounced.cancel = _debounced.cancel;
  debounced.flush = flush;
  return debounced;
}
function throttle(func, throttleMs = 0, options = {}) {
  const { leading = true, trailing = true } = options;
  return debounce(func, throttleMs, {
    leading,
    maxWait: throttleMs,
    trailing
  });
}
function toNumber(value) {
  if (isSymbol(value)) return NaN;
  return Number(value);
}
function toFinite(value) {
  if (!value) return value === 0 ? value : 0;
  value = toNumber(value);
  if (value === Infinity || value === -Infinity) return (value < 0 ? -1 : 1) * Number.MAX_VALUE;
  return value === value ? value : 0;
}
function range(start, end, step) {
  if (step && typeof step !== "number" && isIterateeCall(start, end, step)) end = step = void 0;
  start = toFinite(start);
  if (end === void 0) {
    end = start;
    start = 0;
  } else end = toFinite(end);
  step = step === void 0 ? start < end ? 1 : -1 : toFinite(step);
  const length = Math.max(Math.ceil((end - start) / (step || 1)), 0);
  const result = new Array(length);
  for (let index = 0; index < length; index++) {
    result[index] = start;
    start += step;
  }
  return result;
}
function isPlainObject(object) {
  if (typeof object !== "object") return false;
  if (object == null) return false;
  if (Object.getPrototypeOf(object) === null) return true;
  if (Object.prototype.toString.call(object) !== "[object Object]") {
    const tag = object[Symbol.toStringTag];
    if (tag == null) return false;
    if (!Object.getOwnPropertyDescriptor(object, Symbol.toStringTag)?.writable) return false;
    return object.toString() === `[object ${tag}]`;
  }
  let proto = object;
  while (Object.getPrototypeOf(proto) !== null) proto = Object.getPrototypeOf(proto);
  return Object.getPrototypeOf(object) === proto;
}
export {
  get as g,
  isPlainObject as i,
  range as r,
  sortBy as s,
  throttle as t,
  uniqBy as u
};
