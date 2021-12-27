const idRegex = /^[a-f\d]{24}$/i;

export const isMongoId = (id: unknown): id is string => typeof id === 'string'
    && idRegex.test(id);

const oneDayToSeconds = 24 * 60 * 60;
