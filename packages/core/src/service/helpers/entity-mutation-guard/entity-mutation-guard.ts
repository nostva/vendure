import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { Permission } from '@vendure/common/lib/generated-types';
import { ID, Type } from '@vendure/common/lib/shared-types';
import { DataSource } from 'typeorm';

import { RequestContext } from '../../../api';
import { ChannelAware, ForbiddenError, TranslatedInput } from '../../../common';
import { TransactionalConnection } from '../../../connection';
import { VendureEntity } from '../../../entity';

export interface AssertMutationPermittedOptions<T> {
    ctx: RequestContext;
    entityType: Type<T>;
    input: TranslatedInput<T> | (TranslatedInput<T> & { id: ID });
    isUpdateOperation?: boolean;
}

@Injectable()
export class EntityMutationGuard {
    constructor(
        @InjectDataSource()
        private dataSource: DataSource,
        private connection: TransactionalConnection,
    ) {}

    async assertMutationPermitted<T extends VendureEntity>(options: AssertMutationPermittedOptions<T>) {
        const { ctx, entityType, input, isUpdateOperation } = options;
        const hasPermission = ctx.userHasPermissions([Permission.SuperAdmin]);

        const inputSpecifiesGlobal = 'global' in input && input.global !== undefined;
        if (isUpdateOperation) {
            const entityMetadata = this.dataSource.getMetadata(entityType);
            const isChannelAware = entityMetadata.relations.some(r => r.propertyName === 'channels');

            const entity = await this.connection.getEntityOrThrow(
                ctx,
                entityType,
                (input as any).id,
                isChannelAware ? { relations: ['channels'] } : undefined,
            );

            if (isChannelAware) {
                const entityWithChannels = entity as T & ChannelAware;
                const entityChannelIds = entityWithChannels.channels.map(c => c.id);
                const userChannelIds = ctx.session?.user?.channelPermissions?.map(c => c.id) ?? [];

                if (!this.arraysIntersect(entityChannelIds, userChannelIds)) {
                    throw new ForbiddenError();
                }

                if (inputSpecifiesGlobal) {
                    const isChangingGlobal = entityWithChannels.global !== input.global;
                    if (isChangingGlobal && !hasPermission) {
                        throw new ForbiddenError();
                    }
                }
            }
        } else {
            if (inputSpecifiesGlobal && !hasPermission) {
                throw new ForbiddenError();
            }
        }
    }

    /**
     * Returns true if any element of arr1 appears in arr2.
     */
    private arraysIntersect<T>(arr1: T[], arr2: T[]): boolean {
        return arr1.reduce((intersects, role) => {
            return intersects || arr2.includes(role);
        }, false as boolean);
    }
}
